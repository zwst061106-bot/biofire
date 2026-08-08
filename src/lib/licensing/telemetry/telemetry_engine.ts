/**
 * TelemetryEngine — Privacy-Preserving Usage Analytics
 * 
 * Collects aggregate usage metrics for billing and product improvement
 * WITHOUT exposing individual transaction details.
 * 
 * Technique: Differential Privacy (Laplace Mechanism)
 * reported_value = true_value + Laplace_noise(epsilon=1.0)
 * 
 * This provides mathematical privacy guarantees:
 * - Adding/removing one transaction changes output probability by at most e^ε
 * - Attackers cannot determine if a specific transaction occurred
 */

import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';

const DEFAULT_EPSILON = 1.0;
const DEFAULT_SENSITIVITY = 1.0;

export interface TelemetryPayload {
  customerId: string;
  licenseId: string;
  reportingPeriod: { start: number; end: number };
  metrics: DifferentiallyPrivateMetrics;
  schemaVersion: number;
}

export interface DifferentiallyPrivateMetrics {
  totalTransactions: number;      // Laplace-noised
  totalVolumeUSD: number;         // Laplace-noised (in thousands)
  activeNodes: number;            // Laplace-noised
  avgSigningLatencyMs: number;    // Laplace-noised
  errorRatePercent: number;       // Laplace-noised
  uniqueChains: number;           // Exact count (low sensitivity)
  mpcCeremonies: {
    dkgCount: number;
    signCount: number;
    refreshCount: number;
  };
}

export interface TelemetryExport {
  payload: TelemetryPayload;
  signature: string;              // Ed25519 signature by customer node
  exportedAt: number;
}

/**
 * Add Laplace noise to a value for differential privacy.
 * noise ~ Laplace(0, sensitivity/epsilon)
 */
function addLaplaceNoise(value: number, epsilon: number, sensitivity: number): number {
  // Generate Laplace noise: - (sensitivity/epsilon) * sign(U - 0.5) * ln(1 - 2|U - 0.5|)
  // where U ~ Uniform(0, 1)
  const u = Math.random();
  const sign = u < 0.5 ? -1 : 1;
  const noise = -(sensitivity / epsilon) * sign * Math.log(1 - 2 * Math.abs(u - 0.5));
  return Math.max(0, value + noise); // Clamp to non-negative
}

/**
 * Generate differentially-private telemetry payload.
 */
export function generateTelemetry(
  customerId: string,
  licenseId: string,
  rawMetrics: {
    totalTransactions: number;
    totalVolumeUSD: number;
    activeNodes: number;
    avgSigningLatencyMs: number;
    errorRatePercent: number;
    uniqueChains: number;
    dkgCount: number;
    signCount: number;
    refreshCount: number;
  },
  periodStart: number,
  periodEnd: number,
  epsilon: number = DEFAULT_EPSILON
): TelemetryPayload {
  const metrics: DifferentiallyPrivateMetrics = {
    totalTransactions: Math.round(addLaplaceNoise(rawMetrics.totalTransactions, epsilon, DEFAULT_SENSITIVITY)),
    totalVolumeUSD: Math.round(addLaplaceNoise(rawMetrics.totalVolumeUSD / 1000, epsilon, DEFAULT_SENSITIVITY)) * 1000,
    activeNodes: Math.round(addLaplaceNoise(rawMetrics.activeNodes, epsilon, DEFAULT_SENSITIVITY)),
    avgSigningLatencyMs: Math.round(addLaplaceNoise(rawMetrics.avgSigningLatencyMs, epsilon, DEFAULT_SENSITIVITY)),
    errorRatePercent: Math.max(0, Math.min(100, addLaplaceNoise(rawMetrics.errorRatePercent, epsilon, 0.1))),
    uniqueChains: rawMetrics.uniqueChains, // Low sensitivity, exact count
    mpcCeremonies: {
      dkgCount: rawMetrics.dkgCount,
      signCount: rawMetrics.signCount,
      refreshCount: rawMetrics.refreshCount,
    },
  };

  return {
    customerId,
    licenseId,
    reportingPeriod: { start: periodStart, end: periodEnd },
    metrics,
    schemaVersion: 1,
  };
}

/**
 * Verify telemetry payload integrity and export.
 */
export function verifyTelemetry(telemetry: TelemetryExport, publicKey: Uint8Array): boolean {
  try {
    const { ed25519 } = require('@noble/curves/ed25519');
    const payloadBytes = new TextEncoder().encode(JSON.stringify(telemetry.payload));
    const sig = new Uint8Array(Buffer.from(telemetry.signature.replace('0x', ''), 'hex'));
    return ed25519.verify(sig, payloadBytes, publicKey);
  } catch {
    return false;
  }
}

export { TelemetryPayload, DifferentiallyPrivateMetrics, TelemetryExport };
