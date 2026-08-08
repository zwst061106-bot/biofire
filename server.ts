/**
 * BioFire-MPC v6.0 Production Server
 * Express API with security headers, rate limiting, input validation,
 * and structured logging.
 */

import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import compression from 'compression';
import rateLimit from 'express-rate-limit';
import dotenv from 'dotenv';
import { createClient } from 'redis';
import { register } from 'prom-client';
import winston from 'winston';

import { MPCCMPEngine } from './src/lib/protocol/mpc_cmp.js';
import { PolicyEngine } from './src/lib/policy/policy_engine.js';
import { AuditChainEngine } from './src/lib/audit/audit_chain.js';
import { HSMEnclaveSimulator } from './src/lib/crypto/hsm_enclave.js';
import { validateAddress, validateAmount, validateChainId, validateMPCParams } from './src/lib/security/input_sanitization.js';
import { SessionBoundKeyGuard } from './src/lib/security/session_guard.js';
import { metricsRegistry } from './src/lib/monitoring/metrics.js';
import type { ChainId, CurveType } from './src/types.js';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;
const METRICS_PORT = process.env.METRICS_PORT || 9090;
const EXPECTED_API_KEY = process.env.BIOFIRE_API_KEY;

if (!EXPECTED_API_KEY || EXPECTED_API_KEY === 'dev-api-key') {
  console.error('FATAL: BIOFIRE_API_KEY must be set to a secure value in production');
  process.exit(1);
}

// Logger
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
    new winston.transports.File({ filename: 'logs/combined.log' }),
  ],
});

// Redis client for rate limiting
const redisClient = createClient({ url: process.env.REDIS_URL });
redisClient.connect().catch(() => logger.warn('Redis not available, falling back to memory rate limit'));

// Rate limiter
const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 120,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req: Request) => req.ip || 'unknown',
  handler: (_req, res) => {
    res.status(429).json({ error: 'Too many requests' });
  },
});

// Middleware
app.use(helmet());
app.use(compression());
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:5173'],
  credentials: true,
}));
app.use(express.json({ limit: '10kb' }));
app.use(limiter);

// API Key middleware
const requireApiKey = (req: Request, res: Response, next: NextFunction) => {
  const key = req.headers['x-api-key'];
  if (key !== EXPECTED_API_KEY) {
    logger.warn('Unauthorized API access attempt', { ip: req.ip });
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
};

// BigInt JSON serializer
(BigInt.prototype as any).toJSON = function () {
  return this.toString();
};

// Health check
app.get('/api/v6/health', (_req, res) => {
  res.json({
    status: 'healthy',
    version: '6.0.0-production',
    timestamp: new Date().toISOString(),
  });
});

// Metrics
app.get('/metrics', async (_req, res) => {
  res.set('Content-Type', register.contentType);
  res.end(await register.metrics());
});

// DKG
app.post('/api/v6/mpc/dkg', requireApiKey, async (req, res) => {
  try {
    const { threshold, totalParties, curve } = req.body;
    const validation = validateMPCParams(threshold, totalParties);
    if (!validation.valid) {
      return res.status(400).json({ error: validation.error });
    }
    const session = await MPCCMPEngine.executeDKG(threshold, totalParties, (curve as CurveType) || 'secp256k1');
    AuditChainEngine.appendLog('DKG_INITIATED', 'API', `Session ${session.sessionId} with threshold ${threshold}-of-${totalParties}`);
    metricsRegistry.incDKG();
    res.json(session);
  } catch (err) {
    logger.error('DKG failed', { error: (err as Error).message });
    res.status(500).json({ error: 'DKG failed' });
  }
});

// Signing
app.post('/api/v6/mpc/sign', requireApiKey, async (req, res) => {
  try {
    const { chainId, amount, symbol, toAddress, dropNodeId } = req.body;

    if (!validateChainId(chainId)) {
      return res.status(400).json({ error: 'Invalid chainId' });
    }
    const amountValidation = validateAmount(amount);
    if (!amountValidation.valid) {
      return res.status(400).json({ error: amountValidation.error });
    }
    if (!validateAddress(toAddress)) {
      return res.status(400).json({ error: 'Invalid destination address' });
    }

    // Policy check
    const amountUSD = parseFloat(amount) * 3200;
    const sim = PolicyEngine.simulateTransaction(chainId as ChainId, toAddress, amountUSD);
    const policyResult = PolicyEngine.evaluatePolicy(chainId as ChainId, toAddress, amountUSD, sim);

    if (!policyResult.allowed) {
      metricsRegistry.incPolicyViolation();
      AuditChainEngine.appendLog('POLICY_BLOCKED', 'POLICY_ENGINE', `Blocked tx to ${toAddress}: ${policyResult.rejectionReasons.join(', ')}`);
      return res.status(403).json({ error: 'TRANSACTION_BLOCKED_BY_POLICY', policyResult });
    }

    const ceremony = await MPCCMPEngine.executeThresholdSigning(chainId, amount, symbol, toAddress, dropNodeId);
    metricsRegistry.incSigningOps();
    AuditChainEngine.appendLog('SIGNING_COMPLETED', 'API', `Ceremony ${ceremony.ceremonyId} for ${amount} ${symbol}`);

    res.json({ ceremony });
  } catch (err) {
    logger.error('Signing failed', { error: (err as Error).message });
    res.status(500).json({ error: 'Signing failed' });
  }
});

// Audit
app.get('/api/v6/audit/verify', requireApiKey, (_req, res) => {
  const result = AuditChainEngine.verifyChainIntegrity();
  res.json(result);
});

app.get('/api/v6/audit/logs', requireApiKey, (req, res) => {
  const limit = parseInt(req.query.limit as string) || 100;
  const logs = AuditChainEngine.getLogs(limit);
  res.json(logs);
});

// HSM
app.get('/api/v6/hsm/status', requireApiKey, (_req, res) => {
  res.json(HSMEnclaveSimulator.getStatus());
});

app.post('/api/v6/hsm/tamper', requireApiKey, (_req, res) => {
  const status = HSMEnclaveSimulator.triggerTamperAlert();
  AuditChainEngine.appendLog('HSM_TAMPER', 'SECURITY', 'HSM tamper alert triggered');
  res.json(status);
});

// Start
app.listen(PORT, () => {
  logger.info(`BioFire-MPC v6.0 listening on port ${PORT}`);
});

// Metrics server
express().get('/metrics', async (_req, res) => {
  res.set('Content-Type', register.contentType);
  res.end(await register.metrics());
}).listen(METRICS_PORT, () => {
  logger.info(`Metrics server on port ${METRICS_PORT}`);
});
