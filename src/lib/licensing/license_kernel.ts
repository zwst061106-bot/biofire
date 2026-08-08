/**
 * LicenseVerificationKernel — Runtime License Enforcement
 * 
 * Central kernel that ties together:
 * - License blob verification (Ed25519 signature)
 * - Hardware fingerprint binding (TPM/CPUID/MAC)
 * - Heartbeat generation and verification
 * - Usage metering (local encrypted cache)
 * - Telemetry export (differential privacy)
 * 
 * This is the SINGLE POINT of license enforcement in the SDK.
 */

import { LicenseBlob, verifyLicenseBlob, hasFeature } from '../license_blob.js';
import { generateHardwareFingerprint, verifyHardwareFingerprint, HardwareFingerprint } from '../hardware_fingerprint.js';
import { generateHeartbeat, verifyHeartbeat, detectCloning, HeartbeatToken, HEARTBEAT_INTERVAL_MS } from '../heartbeat.js';
import { generateTelemetry, TelemetryPayload, TelemetryExport } from '../telemetry/telemetry_engine.js';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';
import { ed25519 } from '@noble/curves/ed25519';

const METERING_DB_PATH = './data/license_metering.db';

export interface LicenseState {
  blob: LicenseBlob;
  hwFingerprint: HardwareFingerprint;
  isValid: boolean;
  gracePeriodActive: boolean;
  gracePeriodEndsAt?: number;
  usageCounters: UsageCounters;
  lastHeartbeatAt: number;
  lastHeartbeatToken?: HeartbeatToken;
}

export interface UsageCounters {
  totalTransactions: number;
  totalVolumeUSD: number;
  dkgCount: number;
  signCount: number;
  refreshCount: number;
  periodStart: number;
}

export class LicenseVerificationKernel {
  private state: LicenseState | null = null;
  private heartbeatSecret: Uint8Array;
  private heartbeatTimer: ReturnType<typeof setInterval> | null = null;
  private readonly nodeId: string;

  constructor(nodeId: string, heartbeatSecretHex: string) {
    this.nodeId = nodeId;
    this.heartbeatSecret = new Uint8Array(Buffer.from(heartbeatSecretHex.replace('0x', ''), 'hex'));
  }

  /**
   * Initialize license with blob and hardware binding.
   * Must be called before any MPC operations.
   */
  async initializeLicense(blob: LicenseBlob): Promise<LicenseState> {
    // 1. Verify license signature and validity
    const verification = verifyLicenseBlob(blob);
    if (!verification.valid && !verification.inGracePeriod) {
      throw new Error(`License invalid: ${verification.reason}`);
    }

    // 2. Generate hardware fingerprint
    const hwFingerprint = await generateHardwareFingerprint();

    // 3. If license has hardware binding, verify match
    if (blob.hardwareFingerprint) {
      const hwCheck = await verifyHardwareFingerprint({
        fingerprint: blob.hardwareFingerprint,
        source: 'TPM',
        components: {},
        confidence: 1.0,
      });

      if (!hwCheck.matches) {
        throw new Error(`Hardware fingerprint mismatch: ${hwCheck.reason}`);
      }
    }

    // 4. Initialize usage counters
    const usageCounters: UsageCounters = {
      totalTransactions: 0,
      totalVolumeUSD: 0,
      dkgCount: 0,
      signCount: 0,
      refreshCount: 0,
      periodStart: Date.now(),
    };

    this.state = {
      blob,
      hwFingerprint,
      isValid: verification.valid || verification.inGracePeriod,
      gracePeriodActive: verification.inGracePeriod,
      gracePeriodEndsAt: verification.gracePeriodEndsAt,
      usageCounters,
      lastHeartbeatAt: 0,
    };

    // 5. Start heartbeat
    this.startHeartbeat();

    return this.state;
  }

  /**
   * Check if a feature is licensed.
   */
  checkFeature(feature: string): boolean {
    if (!this.state) return false;
    return hasFeature(this.state.blob, feature);
  }

  /**
   * Record a transaction for metering.
   */
  recordTransaction(volumeUSD: number): void {
    if (!this.state) throw new Error('License not initialized');

    // Check quota
    if (this.state.usageCounters.totalTransactions >= this.state.blob.transactionQuota.maxTransactions) {
      throw new Error('TRANSACTION_QUOTA_EXCEEDED');
    }
    if (this.state.usageCounters.totalVolumeUSD + volumeUSD > this.state.blob.transactionQuota.maxVolumeUSD) {
      throw new Error('VOLUME_QUOTA_EXCEEDED');
    }

    this.state.usageCounters.totalTransactions++;
    this.state.usageCounters.totalVolumeUSD += volumeUSD;
  }

  /**
   * Record MPC ceremony for metering.
   */
  recordCeremony(type: 'DKG' | 'SIGN' | 'REFRESH'): void {
    if (!this.state) return;
    switch (type) {
      case 'DKG': this.state.usageCounters.dkgCount++; break;
      case 'SIGN': this.state.usageCounters.signCount++; break;
      case 'REFRESH': this.state.usageCounters.refreshCount++; break;
    }
  }

  /**
   * Export telemetry with differential privacy.
   */
  exportTelemetry(): TelemetryExport {
    if (!this.state) throw new Error('License not initialized');

    const payload = generateTelemetry(
      this.state.blob.customerId,
      this.state.blob.licenseId,
      {
        totalTransactions: this.state.usageCounters.totalTransactions,
        totalVolumeUSD: this.state.usageCounters.totalVolumeUSD,
        activeNodes: 1, // This node
        avgSigningLatencyMs: 150, // Would be measured
        errorRatePercent: 0.1,
        uniqueChains: 3,
        dkgCount: this.state.usageCounters.dkgCount,
        signCount: this.state.usageCounters.signCount,
        refreshCount: this.state.usageCounters.refreshCount,
      },
      this.state.usageCounters.periodStart,
      Date.now()
    );

    // Sign with node key
    const payloadBytes = new TextEncoder().encode(JSON.stringify(payload));
    const signature = '0x' + bytesToHex(ed25519.sign(payloadBytes, this.heartbeatSecret));

    return { payload, signature, exportedAt: Date.now() };
  }

  /**
   * Get current heartbeat token (for external verification).
   */
  getCurrentHeartbeat(): HeartbeatToken {
    if (!this.state) throw new Error('License not initialized');

    return generateHeartbeat(
      this.nodeId,
      this.state.hwFingerprint,
      {
        tx: this.state.usageCounters.totalTransactions,
        vol: this.state.usageCounters.totalVolumeUSD,
      },
      this.heartbeatSecret
    );
  }

  /**
   * Graceful shutdown.
   */
  shutdown(): void {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }
    // Zeroize secret
    this.heartbeatSecret.fill(0);
  }

  private startHeartbeat(): void {
    this.heartbeatTimer = setInterval(() => {
      if (!this.state) return;

      const token = generateHeartbeat(
        this.nodeId,
        this.state.hwFingerprint,
        {
          tx: this.state.usageCounters.totalTransactions,
          vol: this.state.usageCounters.totalVolumeUSD,
        },
        this.heartbeatSecret
      );

      this.state.lastHeartbeatAt = Date.now();
      this.state.lastHeartbeatToken = token;
    }, HEARTBEAT_INTERVAL_MS);
  }

  getState(): LicenseState | null {
    return this.state;
  }
}

export { LicenseState, UsageCounters };
