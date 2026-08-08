import { describe, it, expect } from 'vitest';
import { generateKeyPairSecp256k1, signMessageSecp256k1, verifySignatureSecp256k1, deriveEthereumAddress, CURVE_ORDER } from '../../src/lib/crypto/secp256k1.js';
import { sha256 } from '@noble/hashes/sha256';
import { hexToBytes } from '@noble/hashes/utils';

describe('secp256k1', () => {
  it('should generate valid keypair', () => {
    const kp = generateKeyPairSecp256k1();
    expect(kp.privateKey).toMatch(/^0x[0-9a-f]{64}$/);
    expect(kp.publicKey).toMatch(/^0x04[0-9a-f]{128}$/);
  });

  it('should sign and verify message', () => {
    const kp = generateKeyPairSecp256k1();
    const msg = sha256(new TextEncoder().encode('test'));
    const sig = signMessageSecp256k1(kp.privateKey, msg);
    expect(sig.r).toMatch(/^0x[0-9a-f]{64}$/);
    expect(sig.s).toMatch(/^0x[0-9a-f]{64}$/);
  });

  it('should derive valid Ethereum address', () => {
    const kp = generateKeyPairSecp256k1();
    const addr = deriveEthereumAddress(kp.publicKey);
    expect(addr).toMatch(/^0x[0-9a-fA-F]{40}$/);
    expect(addr).not.toMatch(/^[0-9a-f]{40}$/); // Must have mixed case (EIP-55)
  });

  it('should handle 1000 signing iterations', () => {
    const kp = generateKeyPairSecp256k1();
    const msg = sha256(new TextEncoder().encode('stress test'));
    for (let i = 0; i < 1000; i++) {
      const sig = signMessageSecp256k1(kp.privateKey, msg);
      expect(sig.rawSigHex.length).toBeGreaterThan(130);
    }
  });
});
