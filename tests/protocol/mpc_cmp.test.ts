import { describe, it, expect } from 'vitest';
import { MPCCMPEngine } from '../../src/lib/protocol/mpc_cmp.js';

describe('MPC-CMP Engine', () => {
  it('should execute DKG', async () => {
    MPCCMPEngine.registerNodes([
      { id: 'node-1', url: 'http://localhost:3001' },
      { id: 'node-2', url: 'http://localhost:3002' },
      { id: 'node-3', url: 'http://localhost:3003' },
    ]);
    const session = await MPCCMPEngine.executeDKG(2, 3, 'secp256k1');
    expect(session.sessionId).toBeDefined();
    expect(session.threshold).toBe(2);
    expect(session.totalParties).toBe(3);
    expect(session.masterPublicKey).toMatch(/^0x04/);
    expect(session.phase).toBe('COMPLETED');
  });

  it('should execute threshold signing', async () => {
    const ceremony = await MPCCMPEngine.executeThresholdSigning(
      'ethereum', '1.5', 'ETH', '0x71C7656EC7ab88b098defB751B7401B5f6d8976F'
    );
    expect(ceremony.ceremonyId).toBeDefined();
    expect(ceremony.finalSignature).toBeDefined();
    expect(ceremony.finalSignature?.r).toMatch(/^0x[0-9a-f]{64}$/);
    expect(ceremony.finalSignature?.s).toMatch(/^0x[0-9a-f]{64}$/);
  });

  it('should handle dropped party', async () => {
    const ceremony = await MPCCMPEngine.executeThresholdSigning(
      'ethereum', '0.5', 'ETH', '0x71C7656EC7ab88b098defB751B7401B5f6d8976F', 'node-1'
    );
    expect(ceremony.activeSigners).not.toContain('node-1');
    expect(ceremony.finalSignature).toBeDefined();
  });
});
