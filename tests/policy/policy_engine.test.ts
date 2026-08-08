import { describe, it, expect, beforeEach } from 'vitest';
import { secp256k1 } from '@noble/curves/secp256k1';
import { bytesToHex } from '@noble/hashes/utils';
import { PolicyEngine } from '../../src/lib/policy/policy_engine.js';
import { deriveEVMAddress } from '../../src/lib/crypto/address_derivation.js';

function freshEvmAddress(): string {
  const priv = secp256k1.utils.randomPrivateKey();
  const point = secp256k1.ProjectivePoint.fromPrivateKey(priv);
  return deriveEVMAddress('0x' + bytesToHex(point.toRawBytes(false)));
}

describe('PolicyEngine', () => {
  beforeEach(() => {
    // Reset to known-good defaults before each test so tests don't leak state
    PolicyEngine.updatePolicy({
      enabled: true,
      maxDailySpendingUSD: 2_000_000,
      currentDailySpendingUSD: 0,
      whitelistedAddressesOnly: false,
      blacklistedAddresses: ['0x99999999999999999999999999999999DRAIN0000'],
      maxTransactionAmountUSD: 500_000,
      velocityLimitPerHour: 10,
      blockMaliciousContracts: true,
    });
  });

  it('allows a small, well-formed transaction under all limits', () => {
    const to = freshEvmAddress();
    const result = PolicyEngine.evaluatePolicy('ethereum', to, 100);
    expect(result.allowed).toBe(true);
    expect(result.rejectionReasons.length).toBe(0);
  });

  it('rejects a malformed destination address', () => {
    const result = PolicyEngine.evaluatePolicy('ethereum', '0xnot-a-real-address', 100);
    expect(result.allowed).toBe(false);
    expect(result.rejectionReasons.length).toBeGreaterThan(0);
  });

  it('rejects a blacklisted destination address regardless of amount', () => {
    const result = PolicyEngine.evaluatePolicy(
      'ethereum',
      '0x99999999999999999999999999999999DRAIN0000',
      1
    );
    expect(result.allowed).toBe(false);
    expect(result.riskScore).toBe(100);
  });

  it('enforces whitelist-only mode', () => {
    PolicyEngine.updatePolicy({ whitelistedAddressesOnly: true });
    const to = freshEvmAddress(); // not on whitelist
    const result = PolicyEngine.evaluatePolicy('ethereum', to, 50);
    expect(result.allowed).toBe(false);
    expect(result.rejectionReasons.some(r => r.toLowerCase().includes('whitelist'))).toBe(true);
  });

  it('rejects a transaction that exceeds the daily spending limit', () => {
    PolicyEngine.updatePolicy({ maxDailySpendingUSD: 1000, currentDailySpendingUSD: 900 });
    const to = freshEvmAddress();
    const result = PolicyEngine.evaluatePolicy('ethereum', to, 500);
    expect(result.allowed).toBe(false);
    expect(result.rejectionReasons.some(r => r.toLowerCase().includes('daily spending'))).toBe(true);
  });

  it('flags a malicious contract from simulation results', () => {
    const to = freshEvmAddress();
    const result = PolicyEngine.evaluatePolicy('ethereum', to, 10, {
      isMalicious: true,
      threatCategory: 'DRAINER',
    } as any);
    expect(result.allowed).toBe(false);
    expect(result.riskScore).toBe(100);
  });

  it('requires additional approvals for large transactions', () => {
    const to = freshEvmAddress();
    const result = PolicyEngine.evaluatePolicy('ethereum', to, 150_000);
    expect(result.requiresTimelock).toBe(true);
    expect(result.pendingApprovals).toContain('TREASURY');
  });

  it('enforces the hourly velocity limit per destination address', () => {
    PolicyEngine.updatePolicy({ velocityLimitPerHour: 2 });
    const to = freshEvmAddress();
    PolicyEngine.evaluatePolicy('ethereum', to, 10);
    PolicyEngine.evaluatePolicy('ethereum', to, 10);
    const third = PolicyEngine.evaluatePolicy('ethereum', to, 10);
    expect(third.allowed).toBe(false);
    expect(third.rejectionReasons.some(r => r.toLowerCase().includes('velocity'))).toBe(true);
  });

  it('rejects everything when the policy engine is disabled', () => {
    PolicyEngine.updatePolicy({ enabled: false });
    const to = freshEvmAddress();
    const result = PolicyEngine.evaluatePolicy('ethereum', to, 1);
    expect(result.allowed).toBe(false);
  });

  it('getPolicy returns a copy, not a live reference', () => {
    const policy = PolicyEngine.getPolicy();
    policy.maxDailySpendingUSD = 1;
    expect(PolicyEngine.getPolicy().maxDailySpendingUSD).not.toBe(1);
  });
});
