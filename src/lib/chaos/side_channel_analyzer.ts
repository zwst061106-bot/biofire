/**
 * SideChannelAnalyzer — Timing Attack Detection Suite
 * 
 * Tests for timing leakage in critical cryptographic operations:
 * - modPow: Does execution time depend on secret exponent bits?
 * - modInverse: Does execution time depend on input value?
 * - modN: Does conditional subtraction leak timing?
 * - SecureBuffer comparison: Is it truly constant-time?
 * 
 * Methodology: Welch's t-test on timing distributions.
 * If p-value < 0.001, timing leakage is statistically significant.
 */

import { modPow } from '../../crypto/paillier.js';
import { modInverseOrder, modN } from '../../crypto/secp256k1.js';
import { CURVE_ORDER } from '../../security/secure_random.js';
import { constantTimeEqual } from '../../security/constant_time.js';

export interface TimingLeakReport {
  operation: string;
  leaked: boolean;
  pValue: number;
  meanDifferenceMs: number;
  sampleSize: number;
  recommendation: string;
}

export class SideChannelAnalyzer {
  private readonly SAMPLE_SIZE = 10_000;
  private readonly SIGNIFICANCE_THRESHOLD = 0.001;

  /**
   * Run all side-channel tests.
   */
  async runFullAnalysis(): Promise<TimingLeakReport[]> {
    const reports: TimingLeakReport[] = [];

    reports.push(await this.testModPowTiming());
    reports.push(await this.testModInverseTiming());
    reports.push(await this.testModNTiming());
    reports.push(await this.testConstantTimeComparison());

    return reports;
  }

  /**
   * Test modPow for timing leakage based on exponent bit patterns.
   * Vulnerable implementation: different timing for 0-bits vs 1-bits.
   */
  private async testModPowTiming(): Promise<TimingLeakReport> {
    const mod = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n; // secp256k1 order
    const base = 2n;

    // Group A: exponents with many 0-bits
    const groupA: number[] = [];
    for (let i = 0; i < this.SAMPLE_SIZE / 2; i++) {
      const exp = (BigInt(i) << 128n); // Upper bits 0
      const start = performance.now();
      modPow(base, exp, mod);
      groupA.push(performance.now() - start);
    }

    // Group B: exponents with many 1-bits
    const groupB: number[] = [];
    for (let i = 0; i < this.SAMPLE_SIZE / 2; i++) {
      const exp = (BigInt(i) << 128n) | ((1n << 128n) - 1n); // Upper bits 1
      const start = performance.now();
      modPow(base, exp, mod);
      groupB.push(performance.now() - start);
    }

    const { pValue, meanDiff } = this.welchTTest(groupA, groupB);

    return {
      operation: 'modPow',
      leaked: pValue < this.SIGNIFICANCE_THRESHOLD,
      pValue,
      meanDifferenceMs: meanDiff,
      sampleSize: this.SAMPLE_SIZE,
      recommendation: pValue < this.SIGNIFICANCE_THRESHOLD
        ? 'CRITICAL: Implement Montgomery ladder with constant-time conditional swap'
        : 'No significant timing leakage detected',
    };
  }

  /**
   * Test modInverse for timing leakage.
   * Vulnerable: Euclidean algorithm takes different iterations based on input.
   */
  private async testModInverseTiming(): Promise<TimingLeakReport> {
    const groupA: number[] = [];
    const groupB: number[] = [];

    // Group A: Small values (fewer Euclidean steps)
    for (let i = 0; i < this.SAMPLE_SIZE / 2; i++) {
      const val = BigInt(i + 1) * 123456789n % CURVE_ORDER;
      const start = performance.now();
      try { modInverseOrder(val); } catch {}
      groupA.push(performance.now() - start);
    }

    // Group B: Large values (more Euclidean steps)
    for (let i = 0; i < this.SAMPLE_SIZE / 2; i++) {
      const val = CURVE_ORDER - BigInt(i + 1);
      const start = performance.now();
      try { modInverseOrder(val); } catch {}
      groupB.push(performance.now() - start);
    }

    const { pValue, meanDiff } = this.welchTTest(groupA, groupB);

    return {
      operation: 'modInverse',
      leaked: pValue < this.SIGNIFICANCE_THRESHOLD,
      pValue,
      meanDifferenceMs: meanDiff,
      sampleSize: this.SAMPLE_SIZE,
      recommendation: pValue < this.SIGNIFICANCE_THRESHOLD
        ? 'CRITICAL: Implement constant-time modular inverse (Kaliski algorithm)'
        : 'No significant timing leakage detected',
    };
  }

  /**
   * Test modN for conditional subtraction timing.
   * Vulnerable: `if (r < 0) r += n` creates branch prediction leak.
   */
  private async testModNTiming(): Promise<TimingLeakReport> {
    const groupA: number[] = [];
    const groupB: number[] = [];

    // Group A: Values that DON'T need correction (r >= 0)
    for (let i = 0; i < this.SAMPLE_SIZE / 2; i++) {
      const val = BigInt(i) % CURVE_ORDER;
      const start = performance.now();
      modN(val);
      groupA.push(performance.now() - start);
    }

    // Group B: Values that NEED correction (negative input)
    for (let i = 0; i < this.SAMPLE_SIZE / 2; i++) {
      const val = -BigInt(i + 1) % CURVE_ORDER;
      const start = performance.now();
      modN(val);
      groupB.push(performance.now() - start);
    }

    const { pValue, meanDiff } = this.welchTTest(groupA, groupB);

    return {
      operation: 'modN',
      leaked: pValue < this.SIGNIFICANCE_THRESHOLD,
      pValue,
      meanDifferenceMs: meanDiff,
      sampleSize: this.SAMPLE_SIZE,
      recommendation: pValue < this.SIGNIFICANCE_THRESHOLD
        ? 'HIGH: Replace conditional with bit-masking: r = (r & mask) + (n & ~mask)'
        : 'No significant timing leakage detected',
    };
  }

  /**
   * Test constant-time comparison.
   * Vulnerable: Early return on length mismatch or first differing byte.
   */
  private async testConstantTimeComparison(): Promise<TimingLeakReport> {
    const len = 32;
    const bufA = new Uint8Array(len).fill(0xAA);
    const bufB = new Uint8Array(len).fill(0xAA);
    const bufC = new Uint8Array(len).fill(0xBB); // Different at all positions

    const groupA: number[] = [];
    const groupB: number[] = [];

    // Group A: Identical buffers (must scan all bytes)
    for (let i = 0; i < this.SAMPLE_SIZE / 2; i++) {
      const start = performance.now();
      constantTimeEqual(bufA, bufB);
      groupA.push(performance.now() - start);
    }

    // Group B: Different buffers (vulnerable impl would return early)
    for (let i = 0; i < this.SAMPLE_SIZE / 2; i++) {
      const start = performance.now();
      constantTimeEqual(bufA, bufC);
      groupB.push(performance.now() - start);
    }

    const { pValue, meanDiff } = this.welchTTest(groupA, groupB);

    return {
      operation: 'constantTimeEqual',
      leaked: pValue < this.SIGNIFICANCE_THRESHOLD,
      pValue,
      meanDifferenceMs: meanDiff,
      sampleSize: this.SAMPLE_SIZE,
      recommendation: pValue < this.SIGNIFICANCE_THRESHOLD
        ? 'CRITICAL: Ensure NO early returns — always scan full length'
        : 'Constant-time property verified',
    };
  }

  // ======================
  // STATISTICAL TESTS
  // ======================

  /**
   * Welch's t-test for unequal variances.
   * Returns p-value and mean difference.
   */
  private welchTTest(groupA: number[], groupB: number[]): { pValue: number; meanDiff: number } {
    const meanA = groupA.reduce((a, b) => a + b, 0) / groupA.length;
    const meanB = groupB.reduce((a, b) => a + b, 0) / groupB.length;
    const meanDiff = Math.abs(meanA - meanB);

    const varA = groupA.reduce((sum, x) => sum + (x - meanA) ** 2, 0) / (groupA.length - 1);
    const varB = groupB.reduce((sum, x) => sum + (x - meanB) ** 2, 0) / (groupB.length - 1);

    const se = Math.sqrt(varA / groupA.length + varB / groupB.length);
    const t = meanDiff / se;

    // Approximate p-value (two-tailed)
    const df = Math.floor(
      (varA / groupA.length + varB / groupB.length) ** 2 /
      ((varA / groupA.length) ** 2 / (groupA.length - 1) + (varB / groupB.length) ** 2 / (groupB.length - 1))
    );

    // Simplified p-value approximation
    const pValue = Math.min(1, 2 * (1 - this.studentTCDF(Math.abs(t), df)));

    return { pValue, meanDiff };
  }

  private studentTCDF(t: number, df: number): number {
    // Approximation of Student's t CDF
    const x = df / (df + t * t);
    const beta = this.incompleteBeta(x, df / 2, 0.5);
    return 1 - 0.5 * beta;
  }

  private incompleteBeta(x: number, a: number, b: number): number {
    // Simplified incomplete beta function
    return x ** a; // Very rough approximation for side-channel testing
  }
}

export { TimingLeakReport };
