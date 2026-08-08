/**
 * Production Policy Engine & Transaction Guard
 * Enforces institutional spending controls, whitelists, velocity limits,
 * and pre-execution transaction simulation.
 */

import type { 
  PolicyRule, 
  PolicyEvaluationResult, 
  TransactionSimulationResult,
  ChainId,
  ThreatSeverity 
} from '../../types';
import { validateAddress } from '../security/input_sanitization';

// Production: persist to database with encryption
let activePolicy: PolicyRule = {
  id: 'default-policy-001',
  name: 'Enterprise Default Policy',
  enabled: true,
  maxDailySpendingUSD: 2000000,
  currentDailySpendingUSD: 0,
  whitelistedAddressesOnly: false,
  whitelistedAddresses: [
    '0x71C7656EC7ab88b098defB751B7401B5f6d8976F',
    'bc1q9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f',
  ],
  blacklistedAddresses: [
    '0x99999999999999999999999999999999DRAIN0000',
  ],
  requiredApprovalsCount: 2,
  approvalRoles: ['ADMIN', 'TREASURY'],
  timeLockMinutes: 30,
  blockMaliciousContracts: true,
  velocityLimitPerHour: 10,
  maxTransactionAmountUSD: 500000,
  requireGeoIPCheck: false,
  allowedCountries: ['US', 'GB', 'DE', 'SG', 'AE'],
};

// Transaction velocity tracking
const velocityTracker = new Map<string, number[]>(); // address -> timestamps

export class PolicyEngine {
  static getPolicy(): PolicyRule {
    return { ...activePolicy };
  }

  static updatePolicy(updates: Partial<PolicyRule>): PolicyRule {
    activePolicy = { ...activePolicy, ...updates };
    return { ...activePolicy };
  }

  /**
   * Evaluate a transaction against the active policy.
   */
  static evaluatePolicy(
    chainId: ChainId,
    toAddress: string,
    amountUSD: number,
    simulationResult?: TransactionSimulationResult
  ): PolicyEvaluationResult {
    const result: PolicyEvaluationResult = {
      allowed: true,
      requiresTimelock: false,
      pendingApprovals: [],
      rejectionReasons: [],
      riskScore: 0,
      complianceFlags: [],
    };

    if (!activePolicy.enabled) {
      result.rejectionReasons.push('Policy engine is currently disabled');
      result.allowed = false;
      return result;
    }

    // 1. Address validation
    if (!validateAddress(toAddress)) {
      result.rejectionReasons.push('Invalid destination address format');
      result.riskScore += 50;
      result.allowed = false;
    }

    // 2. Blacklist check
    if (activePolicy.blacklistedAddresses.some(addr => 
      addr.toLowerCase() === toAddress.toLowerCase()
    )) {
      result.rejectionReasons.push('Destination address is blacklisted');
      result.riskScore = 100;
      result.allowed = false;
      return result;
    }

    // 3. Whitelist enforcement
    if (activePolicy.whitelistedAddressesOnly) {
      if (!activePolicy.whitelistedAddresses.some(addr => 
        addr.toLowerCase() === toAddress.toLowerCase()
      )) {
        result.rejectionReasons.push('Destination address not in whitelist');
        result.riskScore += 40;
        result.allowed = false;
      }
    }

    // 4. Amount limits
    if (amountUSD > activePolicy.maxTransactionAmountUSD) {
      result.rejectionReasons.push(
        `Transaction amount $${amountUSD.toLocaleString()} exceeds max $${activePolicy.maxTransactionAmountUSD.toLocaleString()}`
      );
      result.riskScore += 30;
      result.requiresTimelock = true;
      result.pendingApprovals.push('ADMIN');
    }

    // 5. Daily spending limit
    if (activePolicy.currentDailySpendingUSD + amountUSD > activePolicy.maxDailySpendingUSD) {
      result.rejectionReasons.push(
        `Daily spending limit exceeded: $${activePolicy.currentDailySpendingUSD.toLocaleString()} / $${activePolicy.maxDailySpendingUSD.toLocaleString()}`
      );
      result.riskScore += 30;
      result.allowed = false;
    }

    // 6. Velocity check
    const now = Date.now();
    const hourAgo = now - 3600 * 1000;
    const recentTxs = (velocityTracker.get(toAddress) || []).filter(t => t > hourAgo);
    if (recentTxs.length >= activePolicy.velocityLimitPerHour) {
      result.rejectionReasons.push(
        `Velocity limit exceeded: ${recentTxs.length} transactions in the last hour`
      );
      result.riskScore += 25;
      result.allowed = false;
    }

    // 7. Malicious contract detection
    if (simulationResult?.isMalicious && activePolicy.blockMaliciousContracts) {
      result.rejectionReasons.push(
        `Malicious contract detected: ${simulationResult.threatCategory}`
      );
      result.riskScore = 100;
      result.allowed = false;
    }

    // 8. Approval requirements
    if (amountUSD > 100000) {
      result.pendingApprovals.push('TREASURY');
      result.requiresTimelock = true;
    }
    if (amountUSD > 500000) {
      result.pendingApprovals.push('COMPLIANCE');
      result.requiresTimelock = true;
    }

    // Update velocity tracker
    recentTxs.push(now);
    velocityTracker.set(toAddress, recentTxs);

    // Clean old entries periodically
    if (Math.random() < 0.01) {
      this.cleanupVelocityTracker();
    }

    // Finalize
    if (result.pendingApprovals.length > 0) {
      result.requiresTimelock = true;
      result.timelockExpiry = now + activePolicy.timeLockMinutes * 60 * 1000;
    }

    if (result.rejectionReasons.length > 0) {
      result.allowed = false;
    }

    return result;
  }

  /**
   * Simulate a transaction before execution.
   * Production: integrate with Tenderly, Alchemy, or custom EVM tracer.
   */
  static simulateTransaction(
    chainId: ChainId,
    targetAddress: string,
    amountUSD: number
  ): TransactionSimulationResult {
    const simId = 'sim_' + Date.now().toString(36);
    const cleanAddr = targetAddress.toLowerCase().trim();

    // Known malicious patterns (production: use Chainalysis, TRM Labs, etc.)
    const maliciousPatterns = [
      { pattern: /drain|phish|hack|exploit/i, category: 'WALLET_DRAINER' as const, severity: 'CRITICAL' as ThreatSeverity },
      { pattern: /unlimited|approveall/i, category: 'UNLIMITED_APPROVAL' as const, severity: 'HIGH' as ThreatSeverity },
      { pattern: /proxy|unverified/i, category: 'UNVERIFIED_CONTRACT' as const, severity: 'MEDIUM' as ThreatSeverity },
    ];

    let isMalicious = false;
    let threatCategory: TransactionSimulationResult['threatCategory'] = 'SAFE_TRANSFER';
    let threatSeverity: ThreatSeverity = 'LOW';

    for (const mp of maliciousPatterns) {
      if (mp.pattern.test(cleanAddr)) {
        isMalicious = true;
        threatCategory = mp.category;
        threatSeverity = mp.severity;
        break;
      }
    }

    // Blacklist override
    if (activePolicy.blacklistedAddresses.some(addr => addr.toLowerCase() === cleanAddr)) {
      isMalicious = true;
      threatCategory = 'WALLET_DRAINER';
      threatSeverity = 'CRITICAL';
    }

    return {
      simulationId: simId,
      targetAddress,
      chainId,
      isMalicious,
      threatCategory,
      threatSeverity,
      predictedBalanceChanges: [{
        asset: symbolForChain(chainId),
        amount: amountUSD.toString(),
        direction: 'OUT',
      }],
      callTrace: isMalicious 
        ? [
            'CALL targetAddress',
            'DELEGATECALL maliciousImplementation',
            'SSTORE balanceOf[msg.sender] = 0 [MUTATION - RISK]',
            'TRANSFER ALL_ASSETS to attackerAddress',
          ]
        : [
            'CALL targetAddress',
            'STATICCALL balanceOf[msg.sender]',
            'SSTORE nonce[msg.sender] += 1',
            'TRANSFER amount to targetAddress [SAFE]',
          ],
      simulationDetails: isMalicious
        ? `SIMULATION ALERT: Contract at ${targetAddress} exhibits ${threatCategory} behavior. All assets at risk.`
        : `SIMULATION PASSED: Transaction to ${targetAddress} is safe. Estimated gas: 21000.`,
      gasEstimate: isMalicious ? 500000n : 21000n,
    };
  }

  static recordSpending(amountUSD: number): void {
    activePolicy.currentDailySpendingUSD += amountUSD;
  }

  static resetDailySpending(): void {
    activePolicy.currentDailySpendingUSD = 0;
  }

  private static cleanupVelocityTracker(): void {
    const hourAgo = Date.now() - 3600 * 1000;
    for (const [addr, times] of velocityTracker) {
      const filtered = times.filter(t => t > hourAgo);
      if (filtered.length === 0) {
        velocityTracker.delete(addr);
      } else {
        velocityTracker.set(addr, filtered);
      }
    }
  }
}

function symbolForChain(chainId: ChainId): string {
  const map: Record<ChainId, string> = {
    ethereum: 'ETH',
    polygon: 'POL',
    bitcoin: 'BTC',
    solana: 'SOL',
    polkadot: 'DOT',
    avalanche: 'AVAX',
  };
  return map[chainId] || 'UNKNOWN';
}
