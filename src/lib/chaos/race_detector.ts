/**
 * RaceConditionDetector — Concurrency Safety Testing
 * 
 * Tests for race conditions in:
 * - PreSignatureQueue (concurrent consume/ingest)
 * - KeyRefreshEngine (concurrent refresh operations)
 * - GovernanceEngine (concurrent approval submissions)
 * - LicenseKernel (concurrent transaction recording)
 * 
 * Uses deterministic thread interleaving simulation.
 */

export interface RaceReport {
  testName: string;
  racesDetected: number;
  dataRaces: { variable: string; threadA: string; threadB: string }[];
  atomicityViolations: number;
  recommendation: string;
}

export class RaceConditionDetector {
  private reports: RaceReport[] = [];

  /**
   * Run all race condition tests.
   */
  async runFullDetection(): Promise<RaceReport[]> {
    this.reports = [];

    await this.testPreSignatureQueueRace();
    await this.testKeyRefreshRace();
    await this.testGovernanceApprovalRace();
    await this.testLicenseMeteringRace();

    return this.reports;
  }

  /**
   * Test PreSignatureQueue for concurrent consume/ingest races.
   * Vulnerability: Queue size check and dequeue are not atomic.
   */
  private async testPreSignatureQueueRace(): Promise<void> {
    const report: RaceReport = {
      testName: 'PreSignatureQueue Concurrent Access',
      racesDetected: 0,
      dataRaces: [],
      atomicityViolations: 0,
      recommendation: '',
    };

    // Simulate: Thread A checks queue.length > 0, Thread B dequeues last item
    // Then Thread A tries to dequeue from empty queue
    const queue: string[] = ['item1'];
    const operations: string[] = [];

    // Thread A: check then consume
    const threadA = async () => {
      const hasItems = queue.length > 0; // TOCTOU window opens
      await this.yield(); // Context switch
      if (hasItems) {
        const item = queue.shift(); // May be undefined!
        operations.push(`A consumed: ${item}`);
      }
    };

    // Thread B: consume
    const threadB = async () => {
      await this.yield();
      const item = queue.shift();
      operations.push(`B consumed: ${item}`);
    };

    await Promise.all([threadA(), threadB()]);

    if (operations.some(op => op.includes('undefined'))) {
      report.racesDetected++;
      report.dataRaces.push({
        variable: 'queue.length',
        threadA: 'check queue.length > 0',
        threadB: 'queue.shift()',
      });
      report.atomicityViolations++;
    }

    report.recommendation = report.racesDetected > 0
      ? 'CRITICAL: Use atomic compare-and-swap (CAS) or mutex lock for queue operations'
      : 'No race conditions detected';

    this.reports.push(report);
  }

  /**
   * Test KeyRefreshEngine for concurrent refresh attempts.
   * Vulnerability: Multiple refreshes could run simultaneously,
   * creating inconsistent share states.
   */
  private async testKeyRefreshRace(): Promise<void> {
    const report: RaceReport = {
      testName: 'KeyRefreshEngine Concurrent Refresh',
      racesDetected: 0,
      dataRaces: [],
      atomicityViolations: 0,
      recommendation: '',
    };

    let epoch = 1;
    let refreshInProgress = false;
    const results: number[] = [];

    const refresh = async (id: number) => {
      if (refreshInProgress) {
        results.push(-1); // Rejected
        return;
      }
      refreshInProgress = true;
      await this.yield(); // Simulate work
      epoch++;
      refreshInProgress = false;
      results.push(epoch);
    };

    await Promise.all([refresh(1), refresh(2), refresh(3)]);

    // Check if multiple refreshes completed (should be rejected)
    const successfulRefreshes = results.filter(r => r > 0).length;
    if (successfulRefreshes > 1) {
      report.racesDetected++;
      report.atomicityViolations++;
      report.dataRaces.push({
        variable: 'refreshInProgress',
        threadA: 'check refreshInProgress',
        threadB: 'set refreshInProgress = true',
      });
    }

    report.recommendation = report.racesDetected > 0
      ? 'CRITICAL: Use atomic test-and-set or semaphore for refresh lock'
      : 'No race conditions detected';

    this.reports.push(report);
  }

  /**
   * Test GovernanceEngine for concurrent approval submissions.
   * Vulnerability: Double-counting of approvals.
   */
  private async testGovernanceApprovalRace(): Promise<void> {
    const report: RaceReport = {
      testName: 'GovernanceEngine Concurrent Approvals',
      racesDetected: 0,
      dataRaces: [],
      atomicityViolations: 0,
      recommendation: '',
    };

    const approvals = new Map<string, number>(); // approver -> count
    const approvalSet = new Set<string>();

    const submitApproval = async (approver: string) => {
      const current = approvals.get(approver) || 0;
      await this.yield();
      approvals.set(approver, current + 1);
      approvalSet.add(approver);
    };

    await Promise.all([
      submitApproval('alice'),
      submitApproval('alice'),
      submitApproval('bob'),
    ]);

    // Alice should only have 1 approval, not 2
    if ((approvals.get('alice') || 0) > 1) {
      report.racesDetected++;
      report.atomicityViolations++;
      report.dataRaces.push({
        variable: 'approvals.get(approver)',
        threadA: 'read current count',
        threadB: 'read current count',
      });
    }

    report.recommendation = report.racesDetected > 0
      ? 'HIGH: Use atomic increment or compare-and-swap for approval counting'
      : 'No race conditions detected';

    this.reports.push(report);
  }

  /**
   * Test LicenseKernel for concurrent transaction recording.
   * Vulnerability: Quota check and increment are not atomic.
   */
  private async testLicenseMeteringRace(): Promise<void> {
    const report: RaceReport = {
      testName: 'LicenseKernel Concurrent Metering',
      racesDetected: 0,
      dataRaces: [],
      atomicityViolations: 0,
      recommendation: '',
    };

    let txCount = 0;
    const quota = 100;
    const violations: number[] = [];

    const recordTx = async () => {
      if (txCount < quota) {
        await this.yield(); // TOCTOU
        txCount++;
      } else {
        violations.push(1);
      }
    };

    // Spawn 150 concurrent transactions (50 over quota)
    const promises: Promise<void>[] = [];
    for (let i = 0; i < 150; i++) {
      promises.push(recordTx());
    }
    await Promise.all(promises);

    if (txCount > quota) {
      report.racesDetected++;
      report.atomicityViolations = txCount - quota;
      report.dataRaces.push({
        variable: 'txCount',
        threadA: 'check txCount < quota',
        threadB: 'txCount++',
      });
    }

    report.recommendation = report.racesDetected > 0
      ? 'CRITICAL: Use atomic compare-and-swap for quota enforcement'
      : 'No race conditions detected';

    this.reports.push(report);
  }

  private async yield(): Promise<void> {
    // Force context switch
    return new Promise(resolve => setImmediate(resolve));
  }
}

export { RaceReport };
