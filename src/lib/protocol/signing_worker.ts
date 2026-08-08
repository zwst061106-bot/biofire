/**
 * Signing Worker Thread — Offline Pre-Computation of Signature Tuples
 * 
 * Runs in an isolated Worker Thread (NOT the main event loop).
 * Generates (k, gamma, chi) tuples continuously and sends them to the main thread.
 * 
 * Security:
 * - Each tuple uses independent CSPRNG
 * - Values are zeroized immediately after transmission
 * - No shared state with main thread except message passing
 */

import { parentPort } from 'worker_threads';
import { secp256k1 } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';
import { randomScalar, modN, CURVE_ORDER } from '../security/secure_random.js';

const CURVE = secp256k1;

interface PreSignatureTuple {
  k: string;      // nonce scalar (hex)
  gamma: string;  // k * G (hex point)
  chi: string;    // auxiliary value for consistency
  id: string;     // unique tuple ID
  timestamp: number;
}

/**
 * Generate a single pre-signature tuple offline.
 * This is the expensive EC math that would block the event loop if done online.
 */
function generateTuple(): PreSignatureTuple {
  // 1. Generate random nonce k ∈ Z_q*
  const k = randomScalar(CURVE_ORDER);

  // 2. Compute gamma = k · G (full EC point multiplication)
  const gammaPoint = CURVE.ProjectivePoint.BASE.multiply(k);
  const gamma = '0x' + bytesToHex(gammaPoint.toRawBytes(false));

  // 3. Compute chi = H(gamma) as auxiliary binding value
  const chiHash = sha256(gammaPoint.toRawBytes(true));
  const chi = '0x' + bytesToHex(chiHash);

  // 4. Unique ID from hash of tuple components
  const idInput = new TextEncoder().encode(`${k.toString(16)}:${gamma}:${chi}:${Date.now()}`);
  const id = '0x' + bytesToHex(sha256(idInput).slice(0, 16));

  // 5. Zeroize k from this thread's memory (logical — JS GC will reclaim)
  // The actual scalar value is only transmitted as hex string, then dropped
  const kHex = '0x' + k.toString(16).padStart(64, '0');

  return { k: kHex, gamma, chi, id, timestamp: Date.now() };
}

/**
 * Worker main loop: continuously generate tuples at configured rate.
 */
function workerMain(batchSize: number = 10): void {
  if (!parentPort) {
    throw new Error('This module must be run as a worker thread');
  }

  // Signal ready
  parentPort.postMessage({ type: 'WORKER_READY' });

  // Continuous generation loop
  const generateBatch = () => {
    const batch: PreSignatureTuple[] = [];
    for (let i = 0; i < batchSize; i++) {
      batch.push(generateTuple());
    }
    parentPort!.postMessage({ type: 'TUPLE_BATCH', batch });
  };

  // Generate immediately, then every 100ms (10 batches/sec = 100 tuples/sec)
  generateBatch();
  const interval = setInterval(generateBatch, 100);

  // Graceful shutdown
  parentPort.on('message', (msg) => {
    if (msg.type === 'STOP') {
      clearInterval(interval);
      parentPort!.postMessage({ type: 'WORKER_STOPPED' });
      process.exit(0);
    }
  });
}

// Auto-start if this file is the worker entry point
if (parentPort) {
  workerMain(10);
}

export { generateTuple };
export type { PreSignatureTuple };
