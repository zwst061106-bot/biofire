/**
 * LicenseBlob — Cryptographic License Format
 * 
 * Self-contained, Ed25519-signed license with embedded terms.
 * Tamper-proof: any modification invalidates the signature.
 * 
 * Format (TLV binary):
 * [licenseId][customerId][featureFlags][nodeLimit][txQuota]
 * [validityWindow][hardwareFingerprint][signature]
 */

import { ed25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import { BinaryPayloadSerializer } from '../../network/binary_serializer.js';

export type LicenseTier = 'COMMUNITY' | 'STARTUP' | 'BUSINESS' | 'ENTERPRISE' | 'CUSTOM';

export interface LicenseBlob {
  licenseId: string;
  customerId: string;
  tier: LicenseTier;
  featureFlags: string[];        // e.g., ['mpc', 'hsm', 'governance']
  nodeLimit: number;             // Max concurrent MPC nodes
  transactionQuota: {            // Monthly/annual limits
    period: 'MONTHLY' | 'ANNUAL';
    maxTransactions: number;
    maxVolumeUSD: number;
  };
  validityWindow: {
    notBefore: number;           // Unix timestamp
    notAfter: number;
  };
  hardwareFingerprint?: string;  // TPM EKpub hash or CPUID+MAC
  gracePeriodHours: number;      // 72h default
  issuedAt: number;
  signature: string;             // Ed25519 signature by BioFire master key
}

export interface LicenseVerificationResult {
  valid: boolean;
  expired: boolean;
  inGracePeriod: boolean;
  gracePeriodEndsAt?: number;
  reason?: string;
  features: string[];
  nodeLimit: number;
  remainingTxQuota?: number;
}

const BIOFIRE_MASTER_PUBLIC_KEY = process.env.BIOFIRE_LICENSE_MASTER_KEY || 
  '0x0000000000000000000000000000000000000000000000000000000000000000';

/**
 * Sign a license blob with the BioFire master Ed25519 key.
 * (Production: this runs on a secure HSM, never exposed to SDK)
 */
export function signLicenseBlob(
  blob: Omit<LicenseBlob, 'signature'>,
  masterPrivateKey: Uint8Array
): LicenseBlob {
  const serialized = serializeLicenseData(blob);
  const signature = '0x' + bytesToHex(ed25519.sign(serialized, masterPrivateKey));
  return { ...blob, signature };
}

/**
 * Verify license blob signature and validity.
 */
export function verifyLicenseBlob(blob: LicenseBlob): LicenseVerificationResult {
  const now = Date.now();
  const result: LicenseVerificationResult = {
    valid: false,
    expired: false,
    inGracePeriod: false,
    features: blob.featureFlags,
    nodeLimit: blob.nodeLimit,
  };

  // 1. Verify signature
  try {
    const serialized = serializeLicenseData(blob);
    const pub = hexToBytes(BIOFIRE_MASTER_PUBLIC_KEY.replace('0x', ''));
    const sig = hexToBytes(blob.signature.replace('0x', ''));
    if (!ed25519.verify(sig, serialized, pub)) {
      result.reason = 'INVALID_SIGNATURE';
      return result;
    }
  } catch {
    result.reason = 'SIGNATURE_VERIFICATION_FAILED';
    return result;
  }

  // 2. Check validity window
  if (now < blob.validityWindow.notBefore) {
    result.reason = 'NOT_YET_VALID';
    return result;
  }

  if (now > blob.validityWindow.notAfter) {
    result.expired = true;
    const graceEnd = blob.validityWindow.notAfter + blob.gracePeriodHours * 3600 * 1000;
    if (now < graceEnd) {
      result.inGracePeriod = true;
      result.gracePeriodEndsAt = graceEnd;
    } else {
      result.reason = 'EXPIRED';
      return result;
    }
  }

  result.valid = true;
  return result;
}

/**
 * Check if a specific feature is enabled in the license.
 */
export function hasFeature(blob: LicenseBlob, feature: string): boolean {
  return blob.featureFlags.includes(feature);
}

function serializeLicenseData(blob: Omit<LicenseBlob, 'signature'>): Uint8Array {
  const payload = BinaryPayloadSerializer.pack('LICENSE_BLOB', {
    licenseId: blob.licenseId,
    customerId: blob.customerId,
    tier: blob.tier,
    featureFlags: blob.featureFlags,
    nodeLimit: blob.nodeLimit,
    txPeriod: blob.transactionQuota.period,
    txMax: blob.transactionQuota.maxTransactions,
    txVolume: blob.transactionQuota.maxVolumeUSD,
    notBefore: blob.validityWindow.notBefore,
    notAfter: blob.validityWindow.notAfter,
    hwFingerprint: blob.hardwareFingerprint || '',
    graceHours: blob.gracePeriodHours,
    issuedAt: blob.issuedAt,
  });
  return payload.bytes;
}

export { LicenseBlob, LicenseTier, LicenseVerificationResult };
