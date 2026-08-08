import { describe, it, expect, beforeAll } from 'vitest';
import { secp256k1 } from '@noble/curves/secp256k1';
import { generatePaillierKeys, PaillierKeyPair } from '../../src/lib/crypto/paillier.js';
import {
  generateMtARangeProof,
  verifyMtARangeProof,
  executeMtARound1,
  executeMtARound2,
  executeMtADecrypt,
  auditIdentifiableAbort,
} from '../../src/lib/crypto/mta_zkp.js';

const CURVE_ORDER = secp256k1.CURVE.n;

describe('MtA Zero-Knowledge Proofs', () => {
  let keysA: PaillierKeyPair;

  beforeAll(() => {
    keysA = generatePaillierKeys(1024); // small key for test speed
  });

  it('generates a range proof that verifies correctly', () => {
    const secret = 12345n;
    const proof = generateMtARangeProof(keysA.publicKey, secret, 'test');
    expect(verifyMtARangeProof(keysA.publicKey, proof, 'test')).toBe(true);
  });

  it('rejects a proof verified against different context data', () => {
    const secret = 12345n;
    const proof = generateMtARangeProof(keysA.publicKey, secret, 'round1');
    expect(verifyMtARangeProof(keysA.publicKey, proof, 'round2')).toBe(false);
  });

  it('rejects a tampered commitment', () => {
    const secret = 999n;
    const proof = generateMtARangeProof(keysA.publicKey, secret, 'ctx');
    const tampered = { ...proof, commitment: '0x1' };
    expect(verifyMtARangeProof(keysA.publicKey, tampered, 'ctx')).toBe(false);
  });

  it('completes a full MtA exchange so both parties derive consistent additive shares', () => {
    const x = 777n % CURVE_ORDER; // Party A's secret scalar
    const y = 333n % CURVE_ORDER; // Party B's secret scalar

    const round1 = executeMtARound1(keysA.publicKey, x);
    expect(verifyMtARangeProof(keysA.publicKey, round1.proof, 'round1')).toBe(true);

    const round2 = executeMtARound2(keysA.publicKey, round1.ciphertext, y);
    expect(verifyMtARangeProof(keysA.publicKey, round2.proofB, 'round2')).toBe(true);

    const alpha = executeMtADecrypt(keysA.privateKey, keysA.publicKey, round2.ciphertextK);

    // alpha + beta should equal x*y mod q
    const expected = ((x * y) % CURVE_ORDER + CURVE_ORDER) % CURVE_ORDER;
    const actual = ((alpha + round2.shareB) % CURVE_ORDER + CURVE_ORDER) % CURVE_ORDER;
    expect(actual).toBe(expected);
  });

  it('flags a node with a missing commitment as an identifiable abort', () => {
    const report = auditIdentifiableAbort(
      ['node-1', 'node-2'],
      new Map([['node-1', 'commit-1']]),
      new Map(),
      new Map()
    );
    expect(report.aborted).toBe(true);
    expect(report.faultyNodeId).toBe('node-2');
    expect(report.evidence).toBe('MISSING_COMMITMENT');
  });

  it('flags a node with an invalid range proof as an identifiable abort', () => {
    const badProof = { commitment: '0x1', z: '0x1', w: '0x1', challenge: '0x1', isValid: false };
    const report = auditIdentifiableAbort(
      ['node-1'],
      new Map([['node-1', 'commit-1']]),
      new Map([['node-1', badProof]]),
      new Map([['node-1', keysA.publicKey]])
    );
    expect(report.aborted).toBe(true);
    expect(report.evidence).toContain('INVALID_PROOF');
  });

  it('reports no abort when all nodes provide valid proofs', () => {
    const proof = generateMtARangeProof(keysA.publicKey, 42n);
    const report = auditIdentifiableAbort(
      ['node-1'],
      new Map([['node-1', 'commit-1']]),
      new Map([['node-1', proof]]),
      new Map([['node-1', keysA.publicKey]])
    );
    expect(report.aborted).toBe(false);
  });
});
