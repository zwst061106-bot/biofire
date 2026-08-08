/**
 * Production Ed25519 Cryptography
 * Real curve operations for Solana, Polkadot, and other Ed25519 chains.
 */

import { ed25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';

export interface Ed25519KeyPair {
  privateKey: string;
  publicKey: string;
}

export interface Ed25519Signature {
  rawSigHex: string;
  rHex: string;
  sHex: string;
}

/**
 * Generate a real Ed25519 keypair using CSPRNG.
 */
export function generateKeyPairEd25519(): Ed25519KeyPair {
  const priv = ed25519.utils.randomPrivateKey();
  const pub = ed25519.getPublicKey(priv);
  return {
    privateKey: '0x' + bytesToHex(priv),
    publicKey: '0x' + bytesToHex(pub),
  };
}

/**
 * Sign a message using Ed25519.
 */
export function signMessageEd25519(privateKeyHex: string, message: Uint8Array): Ed25519Signature {
  const priv = hexToBytes(privateKeyHex.replace('0x', ''));
  const sig = ed25519.sign(message, priv);
  const hex = bytesToHex(sig);
  return {
    rawSigHex: '0x' + hex,
    rHex: '0x' + hex.slice(0, 64),
    sHex: '0x' + hex.slice(64, 128),
  };
}

/**
 * Verify Ed25519 signature.
 */
export function verifySignatureEd25519(
  publicKeyHex: string,
  message: Uint8Array,
  signatureHex: string
): boolean {
  try {
    const pub = hexToBytes(publicKeyHex.replace('0x', ''));
    const sig = hexToBytes(signatureHex.replace('0x', ''));
    return ed25519.verify(sig, message, pub);
  } catch {
    return false;
  }
}

/**
 * Validate Solana Base58 address.
 */
export function isValidSolanaAddress(address: string): boolean {
  return /^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(address);
}

/**
 * Validate Polkadot SS58 address.
 */
export function isValidPolkadotAddress(address: string): boolean {
  return /^[1-9A-HJ-NP-Za-km-z]{47,48}$/.test(address);
}

export { ed25519, sha256, bytesToHex, hexToBytes };
