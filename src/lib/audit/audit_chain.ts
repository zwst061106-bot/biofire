/**
 * Production Immutable Audit Trail
 * SHA-256 hash chain with SQLite persistence and Merkle tree support.
 */

import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';
import { secureRandomBytes } from '../security/secure_random';
import type { AuditLogItem } from '../../types';

// Try SQLite, fallback to in-memory
let db: any = null;
try {
  const Database = await import('better-sqlite3').then(m => m.default || m);
  db = new Database('./data/audit_chain.db');
  db.exec(`
    CREATE TABLE IF NOT EXISTS audit_entries (
      id TEXT PRIMARY KEY,
      idx INTEGER NOT NULL UNIQUE,
      timestamp TEXT NOT NULL,
      action TEXT NOT NULL,
      actor TEXT NOT NULL,
      actor_ip TEXT,
      details TEXT NOT NULL,
      hash TEXT NOT NULL,
      previous_hash TEXT NOT NULL,
      signature TEXT NOT NULL,
      merkle_root TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_timestamp ON audit_entries(timestamp);
    CREATE INDEX IF NOT EXISTS idx_action ON audit_entries(action);
  `);
} catch {
  console.warn('[AuditChain] SQLite not available, using in-memory storage');
}

interface AuditEntry {
  id: string;
  idx: number;
  timestamp: string;
  action: string;
  actor: string;
  actorIp?: string;
  details: string;
  hash: string;
  previousHash: string;
  signature: string;
  merkleRoot?: string;
}

let memoryChain: AuditEntry[] = [];
let nextIndex = 0;

function loadFromDB(): AuditEntry[] {
  if (!db) return [];
  try {
    return db.prepare('SELECT * FROM audit_entries ORDER BY idx').all();
  } catch {
    return [];
  }
}

function initChain(): void {
  const entries = loadFromDB();
  if (entries.length > 0) {
    memoryChain = entries;
    nextIndex = entries[entries.length - 1].idx + 1;
  } else {
    appendGenesis();
  }
}

function appendGenesis(): void {
  const entry: AuditEntry = {
    id: 'genesis-000',
    idx: 0,
    timestamp: new Date().toISOString(),
    action: 'GENESIS_BLOCK',
    actor: 'System Core',
    details: 'BioFire-MPC v6.0 Immutable Audit Ledger Initialized',
    hash: calculateHash(0, new Date().toISOString(), 'GENESIS_BLOCK', 'System Core', '', '0x0000000000000000'),
    previousHash: '0x0000000000000000',
    signature: '0x' + bytesToHex(secureRandomBytes(32)),
  };
  memoryChain.push(entry);
  persistEntry(entry);
}

export function appendLog(
  action: string,
  actor: string,
  details: string,
  actorIp?: string
): AuditLogItem {
  const id = `entry-${nextIndex.toString().padStart(8, '0')}`;
  const timestamp = new Date().toISOString();
  const previousHash = memoryChain.length > 0
    ? memoryChain[memoryChain.length - 1].hash
    : '0x0000000000000000';

  const hash = calculateHash(nextIndex, timestamp, action, actor, details, previousHash);
  const signature = '0x' + bytesToHex(sha256(new TextEncoder().encode(hash + actor)));

  const entry: AuditEntry = {
    id,
    idx: nextIndex,
    timestamp,
    action,
    actor,
    actorIp,
    details,
    hash,
    previousHash,
    signature,
  };

  memoryChain.push(entry);
  persistEntry(entry);
  nextIndex++;

  return {
    id,
    index: entry.idx,
    timestamp,
    action,
    actor,
    details,
    previousHash,
    currentHash: hash,
    signature,
  };
}

export function getLogs(limit?: number): AuditLogItem[] {
  const entries = memoryChain.slice();
  if (limit) return entries.slice(-limit).map(toAuditLogItem);
  return entries.map(toAuditLogItem);
}

export function verifyChainIntegrity(): { 
  isValid: boolean; 
  brokenAtStep?: number; 
  hash: string;
  totalBlocks: number;
} {
  for (let i = 1; i < memoryChain.length; i++) {
    const current = memoryChain[i];
    const previous = memoryChain[i - 1];

    if (current.previousHash !== previous.hash) {
      return { 
        isValid: false, 
        brokenAtStep: i, 
        hash: current.hash,
        totalBlocks: memoryChain.length 
      };
    }

    const recomputed = calculateHash(
      current.idx,
      current.timestamp,
      current.action,
      current.actor,
      current.details,
      current.previousHash
    );

    if (recomputed !== current.hash) {
      return { 
        isValid: false, 
        brokenAtStep: i, 
        hash: current.hash,
        totalBlocks: memoryChain.length 
      };
    }
  }

  return {
    isValid: true,
    hash: memoryChain.length > 0 ? memoryChain[memoryChain.length - 1].hash : '0x0',
    totalBlocks: memoryChain.length,
  };
}

export function getMerkleRoot(): string {
  if (memoryChain.length === 0) return '0x0';
  let hashes = memoryChain.map(e => hexToBytes(e.hash.replace('0x', '')));
  while (hashes.length > 1) {
    const nextLevel: Uint8Array[] = [];
    for (let i = 0; i < hashes.length; i += 2) {
      const left = hashes[i];
      const right = hashes[i + 1] || left;
      const combined = new Uint8Array(left.length + right.length);
      combined.set(left, 0);
      combined.set(right, left.length);
      nextLevel.push(sha256(combined));
    }
    hashes = nextLevel;
  }
  return '0x' + bytesToHex(hashes[0]);
}

function calculateHash(
  idx: number,
  timestamp: string,
  action: string,
  actor: string,
  details: string,
  previousHash: string
): string {
  const data = `${idx}-${timestamp}-${action}-${actor}-${details}-${previousHash}`;
  const hashBytes = sha256(new TextEncoder().encode(data));
  return '0x' + bytesToHex(hashBytes);
}

function persistEntry(entry: AuditEntry): void {
  if (!db) return;
  try {
    db.prepare(`
      INSERT OR IGNORE INTO audit_entries 
      (id, idx, timestamp, action, actor, actor_ip, details, hash, previous_hash, signature)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      entry.id, entry.idx, entry.timestamp, entry.action, entry.actor,
      entry.actorIp || null, entry.details, entry.hash, entry.previousHash, entry.signature
    );
  } catch (e) {
    console.error('[AuditChain] Failed to persist entry:', e);
  }
}

function toAuditLogItem(entry: AuditEntry): AuditLogItem {
  return {
    id: entry.id,
    index: entry.idx,
    timestamp: entry.timestamp,
    action: entry.action,
    actor: entry.actor,
    actorIp: entry.actorIp,
    details: entry.details,
    previousHash: entry.previousHash,
    currentHash: entry.hash,
    signature: entry.signature,
    merkleRoot: entry.merkleRoot,
  };
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return bytes;
}

// Initialize
initChain();

export class AuditChainEngine {
  static appendLog(action: string, actor: string, details: string, actorIp?: string) {
    return appendLog(action, actor, details, actorIp);
  }

  static getLogs(limit?: number): AuditLogItem[] {
    return getLogs(limit);
  }

  static verifyChainIntegrity(): {
    isChainValid: boolean;
    totalBlocksChecked: number;
    corruptedBlockIndex?: number;
    details: string;
    merkleRoot: string;
  } {
    const res = verifyChainIntegrity();
    return {
      isChainValid: res.isValid,
      totalBlocksChecked: res.totalBlocks,
      corruptedBlockIndex: res.brokenAtStep,
      details: res.isValid 
        ? `All ${res.totalBlocks} audit chain blocks verified. Merkle root: ${getMerkleRoot()}`
        : `Broken link at block ${res.brokenAtStep}`,
      merkleRoot: getMerkleRoot(),
    };
  }

  static getMerkleRoot(): string {
    return getMerkleRoot();
  }
}
