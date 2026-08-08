/**
 * LicenseHeartbeat — Cryptographic Liveness Proof
 * 
 * Generates periodic heartbeat tokens proving the license is active
 * on the original hardware. Prevents license cloning and enables
 * usage-based billing reconciliation.
 * 
 * Token format: HMAC-SHA256(epoch || nodeId || hwFingerprint || usageHash)
 * Epoch increments every 5 minutes, making old tokens invalid.
 */

import { sha256 } from '@noble/hashes/sha256';
import { hmac } from '@noble/hashes/hmac';
import { bytesToHex } from '@noble/hashes/utils';
import { HardwareFingerprint } from '../hardware_fingerprint.js';

const HEARTBEAT_INTERVAL_MS = 5 * 60 * 1000; // 5 minutes
const EPOCH_DURATION_MS = 5 * 60 * 1000;     // 5-minute epochs

export interface HeartbeatToken {
  epoch: number;              // Current epoch number
  nodeId: string;
  hwFingerprint: string;
  usageHash: string;          // Hash of usage counters (privacy-preserving)
  timestamp: number;
  token: string;              // HMAC-SHA256 of above fields
}

export interface HeartbeatVerifier {
  verify(token: HeartbeatToken, secretKey: Uint8Array): boolean;
  isEpochValid(epoch: number): boolean;
  detectCloning(tokens: HeartbeatToken[]): { cloned: boolean; evidence: string };
}

/**
 * Generate a heartbeat token.
 */
export function generateHeartbeat(
  nodeId: string,
  hwFingerprint: HardwareFingerprint,
  usageCounters: Record<string, number>,
  secretKey: Uint8Array
): HeartbeatToken {
  const now = Date.now();
  const epoch = Math.floor(now / EPOCH_DURATION_MS);

  // Hash usage counters (privacy-preserving: only aggregate counts)
  const usageData = JSON.stringify(usageCounters);
  const usageHash = '0x' + bytesToHex(sha256(new TextEncoder().encode(usageData)));

  const tokenData = new TextEncoder().encode(
    `${epoch}:${nodeId}:${hwFingerprint.fingerprint}:${usageHash}:${now}`
  );
  const token = '0x' + bytesToHex(hmac(sha256, secretKey, tokenData));

  return {
    epoch,
    nodeId,
    hwFingerprint: hwFingerprint.fingerprint,
    usageHash,
    timestamp: now,
    token,
  };
}

/**
 * Verify a heartbeat token.
 */
export function verifyHeartbeat(
  token: HeartbeatToken,
  secretKey: Uint8Array,
  expectedHwFingerprint: string
): { valid: boolean; reason?: string } {
  // Check epoch (reject tokens older than 2 epochs = 10 minutes)
  const currentEpoch = Math.floor(Date.now() / EPOCH_DURATION_MS);
  if (Math.abs(currentEpoch - token.epoch) > 2) {
    return { valid: false, reason: 'EPOCH_EXPIRED' };
  }

  // Verify hardware fingerprint
  if (token.hwFingerprint !== expectedHwFingerprint) {
    return { valid: false, reason: 'HARDWARE_MISMATCH' };
  }

  // Recompute and verify HMAC
  const tokenData = new TextEncoder().encode(
    `${token.epoch}:${token.nodeId}:${token.hwFingerprint}:${token.usageHash}:${token.timestamp}`
  );
  const expectedToken = '0x' + bytesToHex(hmac(sha256, secretKey, tokenData));

  if (token.token !== expectedToken) {
    return { valid: false, reason: 'INVALID_HMAC' };
  }

  return { valid: true };
}

/**
 * Detect license cloning by analyzing heartbeat token patterns.
 * If the same license appears on two different hardware fingerprints
 * within the same epoch, it's cloned.
 */
export function detectCloning(
  tokens: HeartbeatToken[],
  licenseId: string
): { cloned: boolean; evidence: string; fingerprints: string[] } {
  const epochHwMap = new Map<number, Set<string>>();

  for (const token of tokens) {
    if (!epochHwMap.has(token.epoch)) {
      epochHwMap.set(token.epoch, new Set());
    }
    epochHwMap.get(token.epoch)!.add(token.hwFingerprint);
  }

  for (const [epoch, fingerprints] of epochHwMap) {
    if (fingerprints.size > 1) {
      return {
        cloned: true,
        evidence: `License ${licenseId} detected on ${fingerprints.size} different hardware instances in epoch ${epoch}`,
        fingerprints: Array.from(fingerprints),
      };
    }
  }

  return { cloned: false, evidence: '', fingerprints: [] };
}

export { HeartbeatToken, HEARTBEAT_INTERVAL_MS };
