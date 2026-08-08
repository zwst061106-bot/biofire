/**
 * BinaryPayloadSerializer — Strict TLV (Type-Length-Value) Binary Encoding
 * 
 * Replaces JSON entirely for MPC network payloads.
 * Guarantees:
 * - Predictable, flat byte layout (no nested JSON parsing)
 * - Strict size limits to prevent DoS / buffer overflow
 * - Type-safe deserialization with boundary checking
 * - No BigInt truncation (full 32-byte scalar encoding)
 * - No floating-point (deterministic integer-only encoding)
 * 
 * Format:
 * [MAGIC:4][VERSION:1][PAYLOAD_LEN:4][TYPE:1][...TLV fields...][CRC32:4]
 * 
 * TLV Field:
 * [FIELD_TYPE:1][FIELD_LEN:4][VALUE:FIELD_LEN bytes]
 */

import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';

const MAGIC = new Uint8Array([0x42, 0x46, 0x4D, 0x50]); // "BFMP"
const VERSION = 0x01;

// Field type constants
const FIELD_TYPES = {
  UINT8:    0x01,
  UINT16:   0x02,
  UINT32:   0x03,
  UINT64:   0x04,
  BIG_INT:  0x05, // 32-byte big-endian scalar
  BYTES:    0x06, // raw bytes with explicit length
  STRING:   0x07, // UTF-8 string
  BOOL:     0x08,
  ARRAY:    0x09, // array of TLV fields
  MAP:      0x0A, // key-value pairs
} as const;

type FieldType = typeof FIELD_TYPES[keyof typeof FIELD_TYPES];

export class SerializationError extends Error {
  constructor(message: string) {
    super(`[BinarySerializer] ${message}`);
    this.name = 'SerializationError';
  }
}

export interface SerializedPayload {
  readonly bytes: Uint8Array;
  readonly type: string;
  readonly hash: string; // SHA-256 of payload for integrity
}

/**
 * BinaryPayloadSerializer — Safe pack/unpack for MPC network messages.
 */
export class BinaryPayloadSerializer {
  private static readonly MAX_PAYLOAD_SIZE = 1024 * 1024; // 1MB hard limit
  private static readonly MAX_FIELD_SIZE = 64 * 1024;       // 64KB per field
  private static readonly MAX_FIELDS = 256;

  /**
   * Pack a structured object into a flat binary payload.
   * 
   * Supported value types:
   * - number → UINT32/UINT64 (auto-detected)
   * - bigint → BIG_INT (32-byte)
   * - Uint8Array → BYTES
   * - string → STRING (max 4KB)
   * - boolean → BOOL
   * - Array → ARRAY (recursive)
   * - Record<string, T> → MAP
   */
  static pack(type: string, data: Record<string, unknown>): SerializedPayload {
    const fields: Uint8Array[] = [];
    let fieldCount = 0;

    for (const [key, value] of Object.entries(data)) {
      if (fieldCount >= this.MAX_FIELDS) {
        throw new SerializationError(`Exceeded max field count: ${this.MAX_FIELDS}`);
      }
      const fieldBytes = this.encodeField(key, value);
      if (fieldBytes.length > this.MAX_FIELD_SIZE) {
        throw new SerializationError(`Field '${key}' exceeds max size ${this.MAX_FIELD_SIZE}`);
      }
      fields.push(fieldBytes);
      fieldCount++;
    }

    // Build header: [MAGIC:4][VERSION:1][PAYLOAD_LEN:4][TYPE_LEN:1][TYPE:var][FIELD_COUNT:2]
    const typeBytes = new TextEncoder().encode(type);
    if (typeBytes.length > 255) throw new SerializationError('Type string too long');

    const fieldCountBytes = new Uint8Array(2);
    fieldCountBytes[0] = (fieldCount >> 8) & 0xFF;
    fieldCountBytes[1] = fieldCount & 0xFF;

    const payloadBody = this.concatArrays(fields);
    const totalLen = 4 + 1 + 4 + 1 + typeBytes.length + 2 + payloadBody.length + 4; // +4 for CRC

    if (totalLen > this.MAX_PAYLOAD_SIZE) {
      throw new SerializationError(`Payload exceeds max size ${this.MAX_PAYLOAD_SIZE}`);
    }

    const payload = new Uint8Array(totalLen);
    let offset = 0;

    // Magic
    payload.set(MAGIC, offset); offset += 4;
    // Version
    payload[offset++] = VERSION;
    // Payload length (excluding magic, version, and CRC)
    const bodyLen = totalLen - 4 - 1 - 4;
    payload[offset++] = (bodyLen >> 24) & 0xFF;
    payload[offset++] = (bodyLen >> 16) & 0xFF;
    payload[offset++] = (bodyLen >> 8) & 0xFF;
    payload[offset++] = bodyLen & 0xFF;
    // Type
    payload[offset++] = typeBytes.length;
    payload.set(typeBytes, offset); offset += typeBytes.length;
    // Field count
    payload.set(fieldCountBytes, offset); offset += 2;
    // Fields
    payload.set(payloadBody, offset); offset += payloadBody.length;
    // CRC32 placeholder (using truncated SHA-256 for simplicity in TS)
    const hash = sha256(payload.slice(0, offset));
    payload.set(hash.slice(0, 4), offset);

    const fullHash = '0x' + bytesToHex(hash);
    return Object.freeze({ bytes: payload, type, hash: fullHash }) as SerializedPayload;
  }

  /**
   * Unpack a binary payload back into a structured object.
   * Performs strict boundary checking at every step.
   */
  static unpack(payload: Uint8Array): { type: string; data: Record<string, unknown>; hash: string } {
    if (payload.length < 12) {
      throw new SerializationError('Payload too small');
    }
    if (payload.length > this.MAX_PAYLOAD_SIZE) {
      throw new SerializationError('Payload exceeds max size');
    }

    // Verify magic
    for (let i = 0; i < 4; i++) {
      if (payload[i] !== MAGIC[i]) {
        throw new SerializationError('Invalid magic bytes');
      }
    }

    // Verify version
    if (payload[4] !== VERSION) {
      throw new SerializationError(`Unsupported version: ${payload[4]}`);
    }

    // Read body length
    const bodyLen = (payload[5] << 24) | (payload[6] << 16) | (payload[7] << 8) | payload[8];
    if (bodyLen !== payload.length - 13) {
      throw new SerializationError('Length mismatch');
    }

    // Verify CRC
    const storedCrc = payload.slice(payload.length - 4);
    const computedHash = sha256(payload.slice(0, payload.length - 4));
    const computedCrc = computedHash.slice(0, 4);
    for (let i = 0; i < 4; i++) {
      if (storedCrc[i] !== computedCrc[i]) {
        throw new SerializationError('CRC mismatch — payload corrupted or tampered');
      }
    }

    let offset = 9;

    // Read type
    const typeLen = payload[offset++];
    if (offset + typeLen > payload.length - 4) {
      throw new SerializationError('Type length out of bounds');
    }
    const type = new TextDecoder().decode(payload.slice(offset, offset + typeLen));
    offset += typeLen;

    // Read field count
    const fieldCount = (payload[offset] << 8) | payload[offset + 1];
    offset += 2;

    const data: Record<string, unknown> = {};
    for (let i = 0; i < fieldCount; i++) {
      const { key, value, newOffset } = this.decodeField(payload, offset);
      data[key] = value;
      offset = newOffset;
    }

    return { type, data, hash: '0x' + bytesToHex(computedHash) };
  }

  // ======================
  // PRIVATE ENCODERS
  // ======================

  private static encodeField(key: string, value: unknown): Uint8Array {
    const keyBytes = new TextEncoder().encode(key);
    if (keyBytes.length > 255) throw new SerializationError('Key too long');

    let typeByte: FieldType;
    let valueBytes: Uint8Array;

    if (typeof value === 'boolean') {
      typeByte = FIELD_TYPES.BOOL;
      valueBytes = new Uint8Array([value ? 1 : 0]);
    } else if (typeof value === 'number') {
      if (value < 0) throw new SerializationError('Negative numbers not supported');
      if (value <= 0xFF) {
        typeByte = FIELD_TYPES.UINT8;
        valueBytes = new Uint8Array([value]);
      } else if (value <= 0xFFFF) {
        typeByte = FIELD_TYPES.UINT16;
        valueBytes = new Uint8Array([(value >> 8) & 0xFF, value & 0xFF]);
      } else if (value <= 0xFFFFFFFF) {
        typeByte = FIELD_TYPES.UINT32;
        valueBytes = new Uint8Array([
          (value >> 24) & 0xFF, (value >> 16) & 0xFF,
          (value >> 8) & 0xFF, value & 0xFF
        ]);
      } else {
        typeByte = FIELD_TYPES.UINT64;
        const big = BigInt(value);
        valueBytes = new Uint8Array(8);
        for (let i = 7; i >= 0; i--) {
          valueBytes[i] = Number(big & 0xFFn);
          big >>= 8n;
        }
      }
    } else if (typeof value === 'bigint') {
      typeByte = FIELD_TYPES.BIG_INT;
      valueBytes = this.bigIntToBytes(value, 32);
    } else if (value instanceof Uint8Array) {
      typeByte = FIELD_TYPES.BYTES;
      valueBytes = value;
    } else if (typeof value === 'string') {
      typeByte = FIELD_TYPES.STRING;
      valueBytes = new TextEncoder().encode(value);
      if (valueBytes.length > 4096) throw new SerializationError('String too long');
    } else if (Array.isArray(value)) {
      typeByte = FIELD_TYPES.ARRAY;
      const parts: Uint8Array[] = [];
      for (const item of value) {
        parts.push(this.encodeField('', item));
      }
      valueBytes = this.concatArrays(parts);
    } else if (value && typeof value === 'object') {
      typeByte = FIELD_TYPES.MAP;
      const parts: Uint8Array[] = [];
      for (const [k, v] of Object.entries(value)) {
        parts.push(this.encodeField(k, v));
      }
      valueBytes = this.concatArrays(parts);
    } else {
      throw new SerializationError(`Unsupported type: ${typeof value}`);
    }

    // [KEY_LEN:1][KEY:var][TYPE:1][VALUE_LEN:4][VALUE:var]
    const result = new Uint8Array(1 + keyBytes.length + 1 + 4 + valueBytes.length);
    let offset = 0;
    result[offset++] = keyBytes.length;
    result.set(keyBytes, offset); offset += keyBytes.length;
    result[offset++] = typeByte;
    result[offset++] = (valueBytes.length >> 24) & 0xFF;
    result[offset++] = (valueBytes.length >> 16) & 0xFF;
    result[offset++] = (valueBytes.length >> 8) & 0xFF;
    result[offset++] = valueBytes.length & 0xFF;
    result.set(valueBytes, offset);

    return result;
  }

  private static decodeField(payload: Uint8Array, offset: number): { key: string; value: unknown; newOffset: number } {
    if (offset >= payload.length - 6) {
      throw new SerializationError('Field header out of bounds');
    }

    const keyLen = payload[offset++];
    if (offset + keyLen > payload.length) {
      throw new SerializationError('Key out of bounds');
    }
    const key = new TextDecoder().decode(payload.slice(offset, offset + keyLen));
    offset += keyLen;

    const typeByte = payload[offset++] as FieldType;
    const valueLen = (payload[offset] << 24) | (payload[offset + 1] << 16) | (payload[offset + 2] << 8) | payload[offset + 3];
    offset += 4;

    if (offset + valueLen > payload.length - 4) {
      throw new SerializationError(`Value out of bounds for field '${key}'`);
    }

    const valueBytes = payload.slice(offset, offset + valueLen);
    offset += valueLen;

    let value: unknown;
    switch (typeByte) {
      case FIELD_TYPES.UINT8: value = valueBytes[0]; break;
      case FIELD_TYPES.UINT16: value = (valueBytes[0] << 8) | valueBytes[1]; break;
      case FIELD_TYPES.UINT32: value = (valueBytes[0] << 24) | (valueBytes[1] << 16) | (valueBytes[2] << 8) | valueBytes[3]; break;
      case FIELD_TYPES.UINT64: {
        let big = 0n;
        for (let i = 0; i < 8; i++) big = (big << 8n) | BigInt(valueBytes[i]);
        value = big;
        break;
      }
      case FIELD_TYPES.BIG_INT: {
        let big = 0n;
        for (let i = 0; i < valueBytes.length; i++) big = (big << 8n) | BigInt(valueBytes[i]);
        value = big;
        break;
      }
      case FIELD_TYPES.BYTES: value = new Uint8Array(valueBytes); break;
      case FIELD_TYPES.STRING: value = new TextDecoder().decode(valueBytes); break;
      case FIELD_TYPES.BOOL: value = valueBytes[0] === 1; break;
      case FIELD_TYPES.ARRAY: {
        const arr: unknown[] = [];
        let arrOffset = 0;
        while (arrOffset < valueBytes.length) {
          const { value: v, newOffset } = this.decodeField(valueBytes, arrOffset);
          arr.push(v);
          arrOffset = newOffset;
        }
        value = arr;
        break;
      }
      case FIELD_TYPES.MAP: {
        const map: Record<string, unknown> = {};
        let mapOffset = 0;
        while (mapOffset < valueBytes.length) {
          const { key: k, value: v, newOffset } = this.decodeField(valueBytes, mapOffset);
          map[k] = v;
          mapOffset = newOffset;
        }
        value = map;
        break;
      }
      default: throw new SerializationError(`Unknown field type: ${typeByte}`);
    }

    return { key, value, newOffset: offset };
  }

  private static bigIntToBytes(value: bigint, byteLength: number): Uint8Array {
    const bytes = new Uint8Array(byteLength);
    let v = value;
    for (let i = byteLength - 1; i >= 0; i--) {
      bytes[i] = Number(v & 0xFFn);
      v >>= 8n;
    }
    return bytes;
  }

  private static concatArrays(arrays: Uint8Array[]): Uint8Array {
    const totalLen = arrays.reduce((sum, a) => sum + a.length, 0);
    const result = new Uint8Array(totalLen);
    let offset = 0;
    for (const a of arrays) {
      result.set(a, offset);
      offset += a.length;
    }
    return result;
  }
}
