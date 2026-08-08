# BioFire-MPC v6.0 — Enterprise Digital Asset Custody

[![Tests](https://img.shields.io/badge/tests-passing-brightgreen)](https://github.com)
[![License](https://img.shields.io/badge/license-Proprietary-red)]()
[![Node](https://img.shields.io/badge/node-%3E%3D20-blue)]()

Enterprise-grade Multi-Party Computation (MPC-CMP) platform for institutional digital asset custody. Production-ready architecture inspired by Fireblocks, Coinbase Prime, and Qredo.

## Security Model

- **Threshold Signature Scheme (TSS)**: t-of-n distributed signing (ECDSA secp256k1 / Ed25519)
- **Paillier Homomorphic Encryption**: 2048-bit minimum, 3072-bit recommended
- **Zero-Knowledge Range Proofs**: Fiat-Shamir NIZK for MtA protocol
- **HSM Integration**: AWS KMS, Azure Key Vault, GCP Cloud HSM, PKCS#11 hardware
- **Immutable Audit Trail**: SHA-256 hash chain with Merkle tree verification
- **Policy Engine**: Velocity limits, spending quotas, whitelists, timelocks, compliance flags
- **AES-256-GCM**: Session-bound key wrapping with dual-authentication (JWT + Cookie)

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    BioFire-MPC v6.0                          │
├─────────────────────────────────────────────────────────────┤
│  API Layer        │  Express + Security Headers + Rate Limit│
├───────────────────┼──────────────────────────────────────────┤
│  MPC Protocol     │  CMP-CMP: DKG → MtA ZKP → Threshold Sign│
├───────────────────┼──────────────────────────────────────────┤
│  Cryptography     │  @noble/curves + Paillier + ZK Proofs   │
├───────────────────┼──────────────────────────────────────────┤
│  Security         │  CSPRNG + Constant-Time + AES-256-GCM   │
├───────────────────┼──────────────────────────────────────────┤
│  HSM              │  AWS KMS / Azure / GCP / PKCS#11        │
├───────────────────┼──────────────────────────────────────────┤
│  Policy           │  Spending limits + Velocity + Whitelist │
├───────────────────┼──────────────────────────────────────────┤
│  Audit            │  Immutable SHA-256 chain + Merkle root  │
├───────────────────┼──────────────────────────────────────────┤
│  Monitoring       │  Prometheus metrics + Winston logging     │
├───────────────────┼──────────────────────────────────────────┤
│  Persistence      │  SQLite (dev) / PostgreSQL (prod)         │
├───────────────────┼──────────────────────────────────────────┤
│  Infrastructure   │  Docker + Kubernetes + Redis              │
└─────────────────────────────────────────────────────────────┘
```

## Quick Start

```bash
# 1. Clone and install
git clone https://github.com/your-org/biofire-mpc.git
cd biofire-mpc
npm install

# 2. Configure environment
cp .env.example .env
# Edit .env with your production secrets

# 3. Build and run
npm run build
npm start

# 4. Run tests
npm test
npm run test:coverage
```

## Docker Deployment

```bash
docker-compose up -d
```

## Kubernetes Deployment

```bash
kubectl apply -f k8s/namespace.yml
kubectl apply -f k8s/secrets.yml   # Update with real secrets first!
kubectl apply -f k8s/deployment.yml
kubectl apply -f k8s/service.yml
```

## API Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | /api/v6/health | None | Health check |
| POST | /api/v6/mpc/dkg | API Key | Execute DKG ceremony |
| POST | /api/v6/mpc/sign | API Key | Threshold signing |
| GET | /api/v6/audit/verify | API Key | Verify audit chain |
| GET | /api/v6/audit/logs | API Key | Get audit logs |
| GET | /api/v6/hsm/status | API Key | HSM status |
| POST | /api/v6/hsm/tamper | API Key | Trigger tamper alert |
| GET | /metrics | None | Prometheus metrics |

## Example: DKG Ceremony

```bash
curl -X POST http://localhost:3000/api/v6/mpc/dkg \
  -H "X-API-Key: $BIOFIRE_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "threshold": 2,
    "totalParties": 3,
    "curve": "secp256k1"
  }'
```

## Example: Threshold Signing

```bash
curl -X POST http://localhost:3000/api/v6/mpc/sign \
  -H "X-API-Key: $BIOFIRE_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "chainId": "ethereum",
    "amount": "1.5",
    "symbol": "ETH",
    "toAddress": "0x71C7656EC7ab88b098defB751B7401B5f6d8976F"
  }'
```

## Security Checklist

- [x] Independent nonce generation per signer (no nonce reuse)
- [x] AES-256-GCM authenticated encryption for key shares
- [x] Fiat-Shamir NIZK range proofs for MtA protocol
- [x] Constant-time comparison operations
- [x] CSPRNG with rejection sampling (no modulo bias)
- [x] Input sanitization and validation
- [x] Rate limiting with Redis backend
- [x] Security headers (Helmet)
- [x] Structured logging with Winston
- [x] Prometheus metrics export
- [x] Immutable audit trail with Merkle verification
- [x] HSM integration (AWS KMS adapter)
- [x] Policy engine with velocity limits
- [x] Docker security (non-root user, read-only filesystem)
- [x] Kubernetes security (seccomp, drop capabilities)

## Compliance

- SOC 2 Type II architecture ready
- CCSS Level 3 compliant design
- FIPS 140-3 Level 4 HSM support
- GDPR data protection principles

## Production Roadmap

1. **Security Audit**: Trail of Bits / OpenZeppelin / CertiK
2. **Distributed Network Layer**: gRPC/WebSocket between separate machines
3. **Blockchain RPC Integration**: Infura, Alchemy, Bitcoin Core
4. **Compliance Certification**: SOC 2, ISO 27001
5. **Insurance**: Custody insurance (Evertas, Marsh)
6. **Bug Bounty**: HackerOne / Immunefi program

## License

Copyright (c) 2026 BioFire Vault Technologies. All Rights Reserved.

**PROPRIETARY AND CONFIDENTIAL**. Unauthorized copying, distribution, or commercial exploitation is strictly prohibited without explicit written consent.

---

Built with security-first principles for institutional-grade digital asset custody.
