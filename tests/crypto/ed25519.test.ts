import { describe, it, expect } from 'vitest';
import { generateKeyPairEd25519, signMessageEd25519, verifySignatureEd25519 } from '../../src/lib/crypto/ed25519.js';
import { sha256 } from '@noble/hashes/sha256';

describe('Ed25519', () => {
  it('should generate valid keypair', () => {
    const kp = generateKeyPairEd25519();
    expect(kp.privateKey).toMatch(/^0x[0-9a-f]{64}$/);
    expect(kp.publicKey).toMatch(/^0x[0-9a-f]{64}$/);
  });

  it('should sign and verify', () => {
    const kp = generateKeyPairEd25519();
    const msg = sha256(new TextEncoder().encode('ed25519 test'));
    const sig = signMessageEd25519(kp.privateKey, msg);
    const valid = verifySignatureEd25519(kp.publicKey, msg, sig.rawSigHex);
    expect(valid).toBe(true);
  });

  it('should reject invalid signature', () => {
    const kp1 = generateKeyPairEd25519();
    const kp2 = generateKeyPairEd25519();
    const msg = sha256(new TextEncoder().encode('test'));
    const sig = signMessageEd25519(kp1.privateKey, msg);
    const valid = verifySignatureEd25519(kp2.publicKey, msg, sig.rawSigHex);
    expect(valid).toBe(false);
  });
});
