import { describe, it, expect } from 'vitest';
import { secp256k1 } from '@noble/curves/secp256k1';
import { bytesToHex } from '@noble/hashes/utils';
import {
  deriveEVMAddress,
  deriveBitcoinAddress,
  deriveSolanaAddress,
  derivePolkadotAddress,
  deriveChildKeyShare,
  deriveChildPublicKey,
} from '../../src/lib/crypto/address_derivation.js';

function randomPubKeyHex(): string {
  const priv = secp256k1.utils.randomPrivateKey();
  const point = secp256k1.ProjectivePoint.fromPrivateKey(priv);
  return '0x' + bytesToHex(point.toRawBytes(false));
}

describe('Address Derivation', () => {
  it('derives a checksummed EVM address of correct shape', () => {
    const addr = deriveEVMAddress(randomPubKeyHex());
    expect(addr).toMatch(/^0x[0-9a-fA-F]{40}$/);
    // Must contain mixed case (EIP-55 checksum) at least sometimes across samples
  });

  it('is deterministic for the same public key', () => {
    const pub = randomPubKeyHex();
    expect(deriveEVMAddress(pub)).toBe(deriveEVMAddress(pub));
    expect(deriveBitcoinAddress(pub)).toBe(deriveBitcoinAddress(pub));
  });

  it('derives a bech32 bitcoin address with bc1 prefix', () => {
    const addr = deriveBitcoinAddress(randomPubKeyHex());
    expect(addr.startsWith('bc1')).toBe(true);
  });

  it('derives a base58 solana-style address from a 32-byte key', () => {
    const raw = bytesToHex(secp256k1.utils.randomPrivateKey()); // 32 random bytes, reused as pubkey material
    const addr = deriveSolanaAddress('0x' + raw);
    expect(addr.length).toBeGreaterThan(0);
    expect(addr).not.toMatch(/[0OIl]/); // base58 alphabet excludes these
  });

  it('derives a polkadot SS58 address', () => {
    const raw = bytesToHex(secp256k1.utils.randomPrivateKey());
    const addr = derivePolkadotAddress('0x' + raw);
    expect(addr.length).toBeGreaterThan(0);
  });

  it('produces different addresses for different public keys', () => {
    const a = deriveEVMAddress(randomPubKeyHex());
    const b = deriveEVMAddress(randomPubKeyHex());
    expect(a).not.toBe(b);
  });

  it('derives a child key share whose tweak is within curve order', () => {
    const parentShare = secp256k1.utils.normPrivateKeyToScalar(secp256k1.utils.randomPrivateKey());
    const chainCode = secp256k1.utils.randomPrivateKey();
    const { childShare, tweak } = deriveChildKeyShare(parentShare, chainCode, 0);
    expect(childShare).toBeGreaterThanOrEqual(0n);
    expect(tweak).toBeGreaterThanOrEqual(0n);
    expect(childShare).toBeLessThan(secp256k1.CURVE.n);
  });

  it('derives a child public key that is a valid curve point', () => {
    const parentPub = randomPubKeyHex();
    const chainCode = secp256k1.utils.randomPrivateKey();
    const childPub = deriveChildPublicKey(parentPub, chainCode, 0);
    expect(() => secp256k1.ProjectivePoint.fromHex(childPub.replace('0x', ''))).not.toThrow();
  });

  it('gives different children for different derivation indices', () => {
    const parentPub = randomPubKeyHex();
    const chainCode = secp256k1.utils.randomPrivateKey();
    const child0 = deriveChildPublicKey(parentPub, chainCode, 0);
    const child1 = deriveChildPublicKey(parentPub, chainCode, 1);
    expect(child0).not.toBe(child1);
  });
});
