/**
 * Production Multi-Chain Address Derivation Engine
 * BIP-32 HD derivation + chain-specific encoding.
 */

import { secp256k1 } from '@noble/curves/secp256k1';
import { keccak_256 } from '@noble/hashes/sha3';
import { sha256 } from '@noble/hashes/sha256';
import { ripemd160 } from '@noble/hashes/ripemd160';
import { hmac } from '@noble/hashes/hmac';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';

const CURVE_ORDER = secp256k1.CURVE.n;
const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function encodeBase58(bytes: Uint8Array): string {
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++;
  const digits: number[] = [0];
  for (let i = zeros; i < bytes.length; i++) {
    let carry = bytes[i];
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j] << 8;
      digits[j] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = (carry / 58) | 0;
    }
  }
  let str = '';
  for (let i = 0; i < zeros; i++) str += '1';
  for (let i = digits.length - 1; i >= 0; i--) str += BASE58_ALPHABET[digits[i]];
  return str;
}

function convertBits(data: Uint8Array, fromBits: number, toBits: number, pad: boolean = true): number[] {
  let acc = 0, bits = 0;
  const result: number[] = [];
  const maxv = (1 << toBits) - 1;
  for (let i = 0; i < data.length; i++) {
    const value = data[i];
    if (value < 0 || value >> fromBits !== 0) return [];
    acc = (acc << fromBits) | value;
    bits += fromBits;
    while (bits >= toBits) {
      bits -= toBits;
      result.push((acc >> bits) & maxv);
    }
  }
  if (pad && bits > 0) result.push((acc << (toBits - bits)) & maxv);
  return result;
}

const BECH32_CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const BECH32_GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

function bech32Polymod(values: number[]): number {
  let chk = 1;
  for (const p of values) {
    const b = chk >> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ p;
    for (let i = 0; i < 5; i++) {
      if ((b >> i) & 1) chk ^= BECH32_GEN[i];
    }
  }
  return chk;
}

function hrpExpand(hrp: string): number[] {
  const ret: number[] = [];
  for (let i = 0; i < hrp.length; i++) ret.push(hrp.charCodeAt(i) >> 5);
  ret.push(0);
  for (let i = 0; i < hrp.length; i++) ret.push(hrp.charCodeAt(i) & 31);
  return ret;
}

function encodeBech32(hrp: string, witnessVersion: number, witnessProgram: Uint8Array): string {
  const data5bit = convertBits(witnessProgram, 8, 5, true);
  const combined = [witnessVersion, ...data5bit];
  const checksumInput = [...hrpExpand(hrp), ...combined, 0, 0, 0, 0, 0, 0];
  const mod = bech32Polymod(checksumInput) ^ 1;
  const checksum: number[] = [];
  for (let p = 0; p < 6; p++) checksum.push((mod >> (5 * (5 - p))) & 31);
  let ret = hrp + '1';
  for (const p of [...combined, ...checksum]) ret += BECH32_CHARSET[p];
  return ret;
}

/**
 * Derive EIP-55 checksummed EVM address.
 */
export function deriveEVMAddress(pubKeyHex: string): string {
  const cleanHex = pubKeyHex.replace(/^0x/, '');
  let pubBytes: Uint8Array;
  if (cleanHex.length === 128) {
    pubBytes = hexToBytes(cleanHex);
  } else if (cleanHex.length === 130 && cleanHex.startsWith('04')) {
    pubBytes = hexToBytes(cleanHex.slice(2));
  } else {
    const point = secp256k1.ProjectivePoint.fromHex(cleanHex);
    pubBytes = point.toRawBytes(false).slice(1);
  }
  const hash = keccak_256(pubBytes);
  const rawAddrHex = bytesToHex(hash.slice(12, 32));
  const hashOfAddr = bytesToHex(keccak_256(new TextEncoder().encode(rawAddrHex)));
  let checksummed = '0x';
  for (let i = 0; i < 40; i++) {
    checksummed += parseInt(hashOfAddr[i], 16) >= 8
      ? rawAddrHex[i].toUpperCase()
      : rawAddrHex[i].toLowerCase();
  }
  return checksummed;
}

/**
 * Derive Bitcoin Native SegWit Bech32 address.
 */
export function deriveBitcoinAddress(pubKeyHex: string): string {
  const cleanHex = pubKeyHex.replace(/^0x/, '');
  let compressedBytes: Uint8Array;
  if (cleanHex.length === 66 && (cleanHex.startsWith('02') || cleanHex.startsWith('03'))) {
    compressedBytes = hexToBytes(cleanHex);
  } else {
    const point = secp256k1.ProjectivePoint.fromHex(cleanHex);
    compressedBytes = point.toRawBytes(true);
  }
  const sha = sha256(compressedBytes);
  const hash160 = ripemd160(sha);
  return encodeBech32('bc', 0, hash160);
}

/**
 * Derive Solana Base58 address from Ed25519 public key.
 */
export function deriveSolanaAddress(pubKeyHex: string): string {
  const cleanHex = pubKeyHex.replace(/^0x/, '');
  const bytes = hexToBytes(cleanHex);
  const pub32 = bytes.length >= 32 ? bytes.slice(0, 32) : bytes;
  return encodeBase58(pub32);
}

/**
 * Derive Polkadot SS58 address.
 */
export function derivePolkadotAddress(pubKeyHex: string): string {
  const cleanHex = pubKeyHex.replace(/^0x/, '');
  const bytes = hexToBytes(cleanHex);
  const pub32 = bytes.slice(0, 32);
  const prefixByte = 0;
  const payload = new Uint8Array([prefixByte, ...pub32]);
  const ss58PrefixStr = new TextEncoder().encode('SS58PRE');
  const checkInput = new Uint8Array(ss58PrefixStr.length + payload.length);
  checkInput.set(ss58PrefixStr, 0);
  checkInput.set(payload, ss58PrefixStr.length);
  const hash = sha256(sha256(checkInput));
  const checksum = hash.slice(0, 2);
  const finalAddrBytes = new Uint8Array(payload.length + checksum.length);
  finalAddrBytes.set(payload, 0);
  finalAddrBytes.set(checksum, payload.length);
  return encodeBase58(finalAddrBytes);
}

/**
 * BIP-32 HD additive key share derivation for threshold custody.
 */
export function deriveChildKeyShare(
  parentShare: bigint,
  chainCode: Uint8Array,
  index: number
): { childShare: bigint; tweak: bigint } {
  const data = new Uint8Array(36);
  data[32] = (index >> 24) & 0xff;
  data[33] = (index >> 16) & 0xff;
  data[34] = (index >> 8) & 0xff;
  data[35] = index & 0xff;
  const hmacOutput = hmac(sha256, chainCode, data);
  let tweak = 0n;
  for (let i = 0; i < 32; i++) tweak = (tweak << 8n) | BigInt(hmacOutput[i]);
  tweak = tweak % CURVE_ORDER;
  const childShare = (parentShare + tweak) % CURVE_ORDER;
  return { childShare, tweak };
}

/**
 * BIP-32 HD master public key derivation.
 */
export function deriveChildPublicKey(
  parentPubKeyHex: string,
  chainCode: Uint8Array,
  index: number
): string {
  const cleanHex = parentPubKeyHex.replace(/^0x/, '');
  const parentPoint = secp256k1.ProjectivePoint.fromHex(cleanHex);
  const data = new Uint8Array(36);
  data[32] = (index >> 24) & 0xff;
  data[33] = (index >> 16) & 0xff;
  data[34] = (index >> 8) & 0xff;
  data[35] = index & 0xff;
  const hmacOutput = hmac(sha256, chainCode, data);
  let tweak = 0n;
  for (let i = 0; i < 32; i++) tweak = (tweak << 8n) | BigInt(hmacOutput[i]);
  tweak = tweak % CURVE_ORDER;
  const tweakPoint = secp256k1.ProjectivePoint.BASE.multiply(tweak);
  const childPoint = parentPoint.add(tweakPoint);
  return '0x' + bytesToHex(childPoint.toRawBytes(false));
}
