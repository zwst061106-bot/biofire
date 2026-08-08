/**
 * Input Sanitization & Validation Utilities
 * Production-grade with strict length limits and injection prevention.
 */

const MAX_INPUT_LENGTH = 10000;
const MAX_ADDRESS_LENGTH = 128;

export class ValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ValidationError';
  }
}

/**
 * Sanitize general text input to prevent XSS and injection attacks.
 */
export function sanitizeInput(input: string, maxLength: number = MAX_INPUT_LENGTH): string {
  if (typeof input !== 'string') return '';
  return input
    .replace(/[<>"'&]/g, '') // Remove potential XSS/injection characters
    .trim()
    .slice(0, maxLength);
}

/**
 * Validate blockchain address format.
 * Supports EVM, Bitcoin (Bech32/Base58), Solana, Polkadot.
 */
export function validateAddress(address: string): boolean {
  if (!address || typeof address !== 'string') return false;
  const cleanAddr = address.trim();
  if (cleanAddr.length > MAX_ADDRESS_LENGTH || cleanAddr.length < 20) return false;

  // EVM Address (EIP-55)
  if (/^0x[a-fA-F0-9]{40}$/.test(cleanAddr)) {
    return validateEIP55Checksum(cleanAddr);
  }

  // Bitcoin Bech32 / Native SegWit
  if (/^(bc1|tb1)[a-zA-Z0-9]{38,59}$/.test(cleanAddr)) {
    return true;
  }

  // Bitcoin Base58 (Legacy / P2SH)
  if (/^[13m][a-km-zA-HJ-NP-Z1-9]{25,34}$/.test(cleanAddr)) {
    return true;
  }

  // Solana Base58
  if (/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(cleanAddr)) {
    return true;
  }

  // Polkadot SS58
  if (/^[1-9A-HJ-NP-Za-km-z]{47,48}$/.test(cleanAddr)) {
    return true;
  }

  return false;
}

/**
 * Validate EIP-55 checksum for Ethereum addresses.
 */
function validateEIP55Checksum(address: string): boolean {
  const addr = address.toLowerCase().replace('0x', '');
  const hash = require('@noble/hashes/sha3').keccak_256(new TextEncoder().encode(addr));
  const hashHex = Array.from(hash).map(b => b.toString(16).padStart(2, '0')).join('');

  for (let i = 0; i < 40; i++) {
    const char = address[i + 2];
    const hashNibble = parseInt(hashHex[i], 16);
    const isUpper = char >= 'A' && char <= 'F';
    const isLower = char >= 'a' && char <= 'f';
    if (isUpper && hashNibble < 8) return false;
    if (isLower && hashNibble >= 8) return false;
  }
  return true;
}

/**
 * Validate amount string is a positive decimal number.
 */
export function validateAmount(amount: string): { valid: boolean; value?: string; error?: string } {
  if (!amount || typeof amount !== 'string') {
    return { valid: false, error: 'Amount must be a string' };
  }
  const trimmed = amount.trim();
  if (!/^\d+(\.\d+)?$/.test(trimmed)) {
    return { valid: false, error: 'Amount must be a positive decimal number' };
  }
  const parts = trimmed.split('.');
  if (parts[1] && parts[1].length > 18) {
    return { valid: false, error: 'Amount precision exceeds 18 decimal places' };
  }
  return { valid: true, value: trimmed };
}

/**
 * Validate chain ID.
 */
export function validateChainId(chainId: string): boolean {
  const validChains = ['ethereum', 'bitcoin', 'solana', 'polygon', 'polkadot', 'avalanche'];
  return validChains.includes(chainId.toLowerCase());
}

/**
 * Validate threshold and total parties for MPC.
 */
export function validateMPCParams(threshold: number, totalParties: number): { valid: boolean; error?: string } {
  if (!Number.isInteger(threshold) || threshold < 2 || threshold > 20) {
    return { valid: false, error: 'threshold must be an integer between 2 and 20' };
  }
  if (!Number.isInteger(totalParties) || totalParties < 2 || totalParties > 50) {
    return { valid: false, error: 'totalParties must be an integer between 2 and 50' };
  }
  if (threshold > totalParties) {
    return { valid: false, error: 'threshold cannot exceed totalParties' };
  }
  return { valid: true };
}
