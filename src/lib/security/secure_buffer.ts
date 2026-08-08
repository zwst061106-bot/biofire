/**
 * SecureBuffer — Zeroization-Protected Memory Buffer
 * 
 * Guarantees:
 * - Data stored in Uint8Array (heap-allocated, not V8 string interning)
 * - Explicit zeroization via .fill(0) on release
 * - No copies exposed outside controlled getters
 * - Timing-safe comparison via constant-time equal
 * 
 * CRITICAL: Always call .release() or use within try/finally.
 */

import { constantTimeEqual } from './constant_time.js';

export class SecureBuffer {
  private _data: Uint8Array | null;
  private _released: boolean = false;
  private readonly _length: number;

  constructor(length: number) {
    this._length = length;
    this._data = new Uint8Array(length);
  }

  static from(data: Uint8Array): SecureBuffer {
    const sb = new SecureBuffer(data.length);
    sb._data!.set(data);
    return sb;
  }

  static fromHex(hex: string): SecureBuffer {
    const clean = hex.startsWith('0x') ? hex.slice(2) : hex;
    const bytes = new Uint8Array(clean.length / 2);
    for (let i = 0; i < clean.length; i += 2) {
      bytes[i / 2] = parseInt(clean.slice(i, i + 2), 16);
    }
    return SecureBuffer.from(bytes);
  }

  /**
   * Get a COPY of the underlying data. Original remains protected.
   */
  get bytes(): Uint8Array {
    if (this._released || !this._data) {
      throw new Error('SecureBuffer: Attempted access after release');
    }
    return new Uint8Array(this._data);
  }

  /**
   * Get data as BigInt. Returns a COPY.
   */
  get asBigInt(): bigint {
    const b = this.bytes;
    let result = 0n;
    for (let i = 0; i < b.length; i++) {
      result = (result << 8n) | BigInt(b[i]);
    }
    return result;
  }

  get length(): number {
    return this._length;
  }

  get isReleased(): boolean {
    return this._released;
  }

  /**
   * Constant-time comparison with another SecureBuffer.
   */
  equals(other: SecureBuffer): boolean {
    if (this._released || other._released) return false;
    if (!this._data || !other._data) return false;
    if (this._data.length !== other._data.length) return false;
    return constantTimeEqual(this._data, other._data);
  }

  /**
   * Overwrite memory with zeros and mark as released.
   * IDEMPOTENT: Safe to call multiple times.
   */
  release(): void {
    if (this._released || !this._data) return;
    this._data.fill(0);
    this._data = null;
    this._released = true;
  }

  /**
   * Auto-release after callback execution.
   */
  static use<T>(sb: SecureBuffer, fn: (data: Uint8Array) => T): T {
    try {
      return fn(sb.bytes);
    } finally {
      sb.release();
    }
  }
}

/**
 * SecureBigInt — Wrapper around bigint with explicit zeroization tracking.
 * Note: JavaScript BigInt is immutable; we track logical zeroization state.
 */
export class SecureBigInt {
  private _value: bigint | null;
  private _released: boolean = false;

  constructor(value: bigint) {
    this._value = value;
  }

  get value(): bigint {
    if (this._released || this._value === null) {
      throw new Error('SecureBigInt: Attempted access after release');
    }
    return this._value;
  }

  get isReleased(): boolean {
    return this._released;
  }

  /**
   * Logical zeroization. Value is dropped; GC will reclaim.
   */
  release(): void {
    this._value = null;
    this._released = true;
  }

  /**
   * Export to SecureBuffer (fixed 32-byte for curve scalars).
   */
  toSecureBuffer(byteLength: number = 32): SecureBuffer {
    const val = this.value;
    const hex = val.toString(16).padStart(byteLength * 2, '0');
    return SecureBuffer.fromHex(hex);
  }

  static fromSecureBuffer(sb: SecureBuffer): SecureBigInt {
    return new SecureBigInt(sb.asBigInt);
  }
}
