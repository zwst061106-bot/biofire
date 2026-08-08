import { describe, it, expect } from 'vitest';
import { appendLog, getLogs, verifyChainIntegrity, getMerkleRoot } from '../../src/lib/audit/audit_chain.js';

describe('Audit Chain', () => {
  it('appends a log entry that links to the previous hash', () => {
    const before = getLogs();
    const prevHash = before.length > 0 ? before[before.length - 1].currentHash : undefined;

    const entry = appendLog('TEST_ACTION', 'test-actor', 'unit test details');

    expect(entry.action).toBe('TEST_ACTION');
    expect(entry.actor).toBe('test-actor');
    expect(entry.currentHash).toMatch(/^0x[0-9a-f]+$/);
    if (prevHash) {
      expect(entry.previousHash).toBe(prevHash);
    }
  });

  it('keeps the chain valid after multiple appends', () => {
    appendLog('ACTION_A', 'actor-a', 'details a');
    appendLog('ACTION_B', 'actor-b', 'details b');
    appendLog('ACTION_C', 'actor-c', 'details c');

    const integrity = verifyChainIntegrity();
    expect(integrity.isValid).toBe(true);
    expect(integrity.totalBlocks).toBeGreaterThanOrEqual(3);
  });

  it('returns logs capped to the requested limit', () => {
    appendLog('LIMIT_TEST_1', 'actor', 'd1');
    appendLog('LIMIT_TEST_2', 'actor', 'd2');
    appendLog('LIMIT_TEST_3', 'actor', 'd3');

    const limited = getLogs(2);
    expect(limited.length).toBe(2);
    expect(limited[1].action).toBe('LIMIT_TEST_3');
  });

  it('produces a stable, non-empty Merkle root over the current chain', () => {
    const rootBefore = getMerkleRoot();
    expect(rootBefore).toMatch(/^0x[0-9a-f]+$/);

    appendLog('MERKLE_TEST', 'actor', 'changes the chain');
    const rootAfter = getMerkleRoot();

    // Adding an entry must change the Merkle root
    expect(rootAfter).not.toBe(rootBefore);
  });

  it('produces a distinct hash for entries with different details', () => {
    const e1 = appendLog('SAME_ACTION', 'same-actor', 'details one');
    const e2 = appendLog('SAME_ACTION', 'same-actor', 'details two');
    expect(e1.currentHash).not.toBe(e2.currentHash);
  });
});
