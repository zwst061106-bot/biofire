/**
 * BioFire-MPC-v6.0 Production Types
 * Enterprise Multi-Party Computation Digital Asset Custody
 */

export type CurveType = 'secp256k1' | 'ed25519' | 'bls12-381';
export type ChainId = 'ethereum' | 'bitcoin' | 'solana' | 'polygon' | 'polkadot' | 'avalanche';

export type MPCPartyRole = 'Client' | 'BlindedEnclave' | 'CoSigner' | 'ComplianceNode' | 'BackupNode';
export type MPCPartyStatus = 'ONLINE' | 'OFFLINE' | 'DEGRADED' | 'MALICIOUS_REJECTED' | 'SYNCING';

export interface MPCParty {
  id: string;
  name: string;
  role: MPCPartyRole;
  status: MPCPartyStatus;
  isEnclave: boolean;
  publicKey?: string;
  publicPaillierN?: string;
  shareCommitment?: string;
  latencyMs: number;
  lastSeenAt: number;
  enclaveAttestationHash?: string;
}

export type DKGPhase = 
  | 'IDLE' 
  | 'ROUND_1_COMMITMENT' 
  | 'ROUND_2_VSS_SHARE' 
  | 'ROUND_3_MTA_EXCHANGE' 
  | 'ROUND_4_CONSISTENCY_VERIFY' 
  | 'COMPLETED' 
  | 'REFRESHING' 
  | 'ABORTED';

export interface DKGSession {
  sessionId: string;
  curve: CurveType;
  threshold: number;
  totalParties: number;
  phase: DKGPhase;
  masterPublicKey: string;
  chainAddresses: Record<ChainId, string>;
  parties: MPCParty[];
  createdAt: number;
  updatedAt: number;
  completedAt?: number;
  auditLogIds: string[];
}

export type SigningRound = 
  | 'ROUND_1_NONCE_COMMITMENT' 
  | 'ROUND_2_MTA_EXCHANGE' 
  | 'ROUND_3_PARTIAL_SIGN' 
  | 'ROUND_4_AGGREGATION' 
  | 'ROUND_5_CONSISTENCY_VERIFY'
  | 'COMPLETED' 
  | 'FAILED';

export interface SigningCeremonyState {
  ceremonyId: string;
  dkgSessionId: string;
  chainId: ChainId;
  curve: CurveType;
  messageHash: string;
  amount: string;
  symbol: string;
  toAddress: string;
  currentRound: SigningRound;
  activeSigners: string[];
  partialSignatures: Record<string, string>;
  nonceCommitments: Record<string, string>;
  mtaProofs: Record<string, boolean>;
  consistencyChecks: Record<string, boolean>;
  finalSignature?: {
    r: string;
    s: string;
    v?: number;
    rawSigHex: string;
  };
  durationMs: number;
  logs: string[];
  createdAt: number;
  completedAt?: number;
}

export type ThreatSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface TransactionSimulationResult {
  simulationId: string;
  targetAddress: string;
  chainId: ChainId;
  isMalicious: boolean;
  threatCategory?: 
    | 'WALLET_DRAINER' 
    | 'UNLIMITED_APPROVAL' 
    | 'UNVERIFIED_CONTRACT' 
    | 'PHISHING_ROUTER' 
    | 'SAFE_TRANSFER'
    | 'SANCTIONED_ADDRESS'
    | 'REENTRANCY_DETECTED';
  threatSeverity: ThreatSeverity;
  predictedBalanceChanges: {
    asset: string;
    amount: string;
    direction: 'IN' | 'OUT';
  }[];
  callTrace: string[];
  simulationDetails: string;
  blockNumber?: number;
  gasEstimate?: bigint;
}

export interface PolicyRule {
  id: string;
  name: string;
  enabled: boolean;
  maxDailySpendingUSD: number;
  currentDailySpendingUSD: number;
  whitelistedAddressesOnly: boolean;
  whitelistedAddresses: string[];
  blacklistedAddresses: string[];
  requiredApprovalsCount: number;
  approvalRoles: ('ADMIN' | 'TREASURY' | 'COMPLIANCE' | 'RISK_OFFICER')[];
  timeLockMinutes: number;
  blockMaliciousContracts: boolean;
  velocityLimitPerHour: number;
  maxTransactionAmountUSD: number;
  requireGeoIPCheck: boolean;
  allowedCountries: string[];
}

export interface PolicyEvaluationResult {
  allowed: boolean;
  requiresTimelock: boolean;
  timelockExpiry?: number;
  pendingApprovals: ('ADMIN' | 'TREASURY' | 'COMPLIANCE' | 'RISK_OFFICER')[];
  rejectionReasons: string[];
  riskScore: number;
  complianceFlags: string[];
}

export interface AuditLogItem {
  id: string;
  index: number;
  timestamp: string;
  action: string;
  actor: string;
  actorIp?: string;
  details: string;
  previousHash: string;
  currentHash: string;
  signature: string;
  merkleRoot?: string;
}

export interface HSMStatus {
  enclaveId: string;
  status: 'SECURE' | 'ATTESTED' | 'TAMPER_ALERT' | 'LOCKED' | 'DEGRADED';
  fipsLevel: 'FIPS 140-2 Level 3' | 'FIPS 140-3 Level 4' | 'FIPS 140-3 Level 5';
  hardwareAttestationHash: string;
  fuzzyExtractorDerived: boolean;
  activeKeysInEnclave: number;
  uptimeSeconds: number;
  lastAttestationAt: number;
  provider: string;
}

export interface BenchmarkMetrics {
  dkgDurationMs: number;
  signingTps: number;
  mtaLatencyMs: number;
  zkpVerifyMs: number;
  auditChainVerifyMs: number;
  activeSimulations: number;
  memoryUsageMB: number;
  cpuUsagePercent: number;
}

export interface PaillierKeyPair {
  n: bigint;
  g: bigint;
  lambda: bigint;
  mu: bigint;
  publicKey: { n: bigint; g: bigint };
  privateKey: { lambda: bigint; mu: bigint };
}

export interface MtAProof {
  commitment: string;
  z: string;
  w: string;
  challenge?: string;
  isValid: boolean;
}

export interface MtARound1Output {
  ciphertext: bigint;
  proof: MtAProof;
}

export interface MtARound2Output {
  ciphertextK: bigint;
  proofB: MtAProof;
  shareB: bigint;
}

export interface AbortReport {
  aborted: boolean;
  faultyNodeId?: string;
  reason?: string;
  evidence?: string;
}

export interface SessionBindingTokens {
  jwtToken: string;
  cookieFingerprint: string;
  sessionId: string;
  expiresAt: number;
}

export interface EncryptedBoundShare {
  shareId: string;
  wrappedDataHex: string;
  ivHex: string;
  saltHex: string;
  authTagHex: string;
  sessionBindingHash: string;
  algorithm: string;
}

export interface SystemMetrics {
  signingOperationsTotal: number;
  dkgCeremoniesTotal: number;
  policyViolationsTotal: number;
  activeMPCParticipants: number;
  hsmAttestationStatus: string;
  uptimeSeconds: number;
  memoryUsageMB: number;
  pendingQueueSize: number;
}

export interface KeyShare {
  nodeId: string;
  share: bigint;
  publicShare: string;
  paillierPublicKey?: { n: bigint; g: bigint };
}

export interface DKGCommitment {
  nodeId: string;
  commitment: string;
  proof: MtAProof;
  timestamp: number;
}
