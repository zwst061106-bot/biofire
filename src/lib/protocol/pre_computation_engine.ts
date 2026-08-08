/**
 * PreComputationEngine — Offline Signature Tuple Generation & Queue Management
 * 
 * Architecture:
 * - Spawns isolated Worker Threads for EC math (no event loop blocking)
 * - Maintains an in-memory queue of pre-computed (k, gamma, chi) tuples
 * - Queue is protected with automatic zeroization on dequeue
 * - Online signing consumes a tuple in a SINGLE non-interactive round
 * 
 * Performance Target: Sub-second signing (typically < 200ms for ECDSA)
 */

import { Worker } from 'worker_threads';
import { EventEmitter } from 'events';
import { secp256k1 } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import { SecureBuffer, SecureBigInt } from '../security/secure_buffer.js';
import { randomScalar, modN, CURVE_ORDER } from '../security/secure_random.js';
import { modInverseOrder } from '../crypto/secp256k1.js';
import type { PreSignatureTuple } from './signing_worker.js';

export interface PreComputationConfig {
  workerCount?: number;        // default: CPU count
  queueTargetSize?: number;    // default: 1000 tuples
  queueMaxSize?: number;       // default: 5000 tuples
  batchSize?: number;          // default: 10 tuples per worker batch
  lowWatermark?: number;     // default: 100 (trigger refill)
}

interface QueuedTuple {
  id: string;
  k: SecureBigInt;       // nonce scalar
  gamma: SecureBuffer;   // k * G point (65 bytes uncompressed)
  chi: SecureBuffer;     // auxiliary hash
  timestamp: number;
}

/**
 * PreComputationEngine — Manages offline pre-signature generation.
 */
export class PreComputationEngine extends EventEmitter {
  private readonly config: Required<PreComputationConfig>;
  private workers: Worker[] = [];
  private queue: QueuedTuple[] = [];
  private queueLock = false;  // Simple lock for queue operations
  private isRunning = false;
  private totalGenerated = 0;
  private totalConsumed = 0;

  constructor(config: PreComputationConfig = {}) {
    super();
    this.config = {
      workerCount: config.workerCount || require('os').cpus().length,
      queueTargetSize: config.queueTargetSize || 1000,
      queueMaxSize: config.queueMaxSize || 5000,
      batchSize: config.batchSize || 10,
      lowWatermark: config.lowWatermark || 100,
    };
  }

  /**
   * Start the pre-computation workers.
   */
  async start(): Promise<void> {
    if (this.isRunning) return;
    this.isRunning = true;

    const workerPath = new URL('./signing_worker.js', import.meta.url).pathname;

    for (let i = 0; i < this.config.workerCount; i++) {
      const worker = new Worker(workerPath, {
        workerData: { batchSize: this.config.batchSize },
      });

      worker.on('message', (msg) => {
        if (msg.type === 'TUPLE_BATCH') {
          this.ingestBatch(msg.batch as PreSignatureTuple[]);
        } else if (msg.type === 'WORKER_READY') {
          this.emit('worker-ready', i);
        }
      });

      worker.on('error', (err) => {
        this.emit('worker-error', { workerId: i, error: err });
      });

      this.workers.push(worker);
    }

    this.emit('started', { workers: this.config.workerCount });
  }

  /**
   * Stop all workers and zeroize the queue.
   */
  async stop(): Promise<void> {
    this.isRunning = false;

    // Signal workers to stop
    for (const worker of this.workers) {
      worker.postMessage({ type: 'STOP' });
    }

    // Wait for graceful shutdown
    await Promise.all(this.workers.map(w => 
      new Promise<void>((resolve) => {
        w.on('exit', resolve);
        setTimeout(resolve, 5000); // Force after 5s
      })
    ));

    this.workers = [];
    this.zeroizeQueue();
    this.emit('stopped');
  }

  /**
   * Consume a pre-computed tuple for online signing.
   * Returns null if queue is empty (should not happen in production with proper sizing).
   * 
   * SECURITY: The returned tuple is REMOVED from the queue and must be
   * zeroized by the caller after use.
   */
  consumeTuple(): QueuedTuple | null {
    if (this.queue.length === 0) {
      this.emit('queue-empty');
      return null;
    }

    const tuple = this.queue.shift()!;
    this.totalConsumed++;

    // Trigger refill if below watermark
    if (this.queue.length < this.config.lowWatermark && this.isRunning) {
      this.emit('queue-low', { current: this.queue.length, target: this.config.queueTargetSize });
    }

    return tuple;
  }

  /**
   * Execute online signing using a pre-computed tuple.
   * This is the FAST path — only scalar arithmetic, no EC point multiplication.
   * 
   * Algorithm:
   * 1. Dequeue pre-computed (k, gamma= k·G)
   * 2. Compute r = x(gamma)
   * 3. Compute s = k⁻¹(z + r·x_i) mod q
   * 4. Zeroize k immediately
   * 
   * Expected latency: < 200ms (vs. 2-5 seconds for full interactive signing)
   */
  executeOnlineSign(
    messageHash: Uint8Array,
    privateShare: SecureBigInt,
    tuple: QueuedTuple
  ): { r: string; s: string; signatureHex: string } {
    try {
      const k = tuple.k.value;
      const gammaBytes = tuple.gamma.bytes;

      // Reconstruct gamma point
      const gammaPoint = secp256k1.ProjectivePoint.fromHex(bytesToHex(gammaBytes).replace('0x', ''));
      const r = modN(gammaPoint.x);

      const z = bytesToBigInt(messageHash);
      const x_i = privateShare.value;

      // s = k⁻¹(z + r·x_i) mod q
      const kInv = modInverseOrder(k);
      const rx = modN(r * x_i);
      const zPlusRx = modN(z + rx);
      const s = modN(kInv * zPlusRx);

      const rHex = '0x' + r.toString(16).padStart(64, '0');
      const sHex = '0x' + s.toString(16).padStart(64, '0');
      const signatureHex = rHex + sHex.slice(2); // concat without 0x prefix on s

      return { r: rHex, s: sHex, signatureHex };
    } finally {
      // CRITICAL: Zeroize the tuple after use
      tuple.k.release();
      tuple.gamma.release();
      tuple.chi.release();
    }
  }

  /**
   * Get queue statistics.
   */
  getStats(): {
    queueSize: number;
    totalGenerated: number;
    totalConsumed: number;
    workersActive: number;
    isRunning: boolean;
  } {
    return {
      queueSize: this.queue.length,
      totalGenerated: this.totalGenerated,
      totalConsumed: this.totalConsumed,
      workersActive: this.workers.length,
      isRunning: this.isRunning,
    };
  }

  // ======================
  // PRIVATE
  // ======================

  private ingestBatch(batch: PreSignatureTuple[]): void {
    if (!this.isRunning) return;
    if (this.queue.length >= this.config.queueMaxSize) {
      this.emit('queue-full');
      return;
    }

    for (const raw of batch) {
      if (this.queue.length >= this.config.queueMaxSize) break;

      const tuple: QueuedTuple = {
        id: raw.id,
        k: SecureBigInt.fromSecureBuffer(SecureBuffer.fromHex(raw.k)),
        gamma: SecureBuffer.fromHex(raw.gamma),
        chi: SecureBuffer.fromHex(raw.chi),
        timestamp: raw.timestamp,
      };

      this.queue.push(tuple);
      this.totalGenerated++;
    }

    this.emit('batch-ingested', { count: batch.length, queueSize: this.queue.length });
  }

  private zeroizeQueue(): void {
    for (const tuple of this.queue) {
      tuple.k.release();
      tuple.gamma.release();
      tuple.chi.release();
    }
    this.queue = [];
  }
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  let hex = '0x';
  for (const b of bytes) hex += b.toString(16).padStart(2, '0');
  return BigInt(hex);
}

export { QueuedTuple };
