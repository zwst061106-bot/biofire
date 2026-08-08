# Changelog

## [6.0.2] - 2026-08-08

### Security
- Upgraded `vitest` and `@vitest/coverage-v8` from v2 to v4, which pulls in a
  patched `vite`/`esbuild`, resolving all 6 `npm audit` findings (2 critical,
  1 high, 3 moderate). These packages were devDependencies only and never
  shipped to production, but are now clean regardless.
- Removed stale `package-lock.json` / `bun.lock` so the next `npm install`
  regenerates a lockfile matching the updated versions.
- **Not yet verified in a live environment** — run `npm install && npm test`
  after pulling this update to confirm the test suite still passes under
  vitest v4 before relying on it.

## [6.0.1] - 2026-08-07

### Fixed
- Critical: `secureRandomBytes()` used `await` inside a non-async function
  (invalid JS/TS), which would fail to compile whenever the Node.js CSPRNG
  fallback path was reached. Replaced with a static top-level `node:crypto`
  import used synchronously.
- Removed unused dependencies (`bullmq`, `node-cron`, `express-validator`)
  that were declared in `package.json` but never referenced anywhere in
  the codebase.

### Tests
- Added coverage for previously untested modules: multi-chain address
  derivation, MtA zero-knowledge proofs (including a full round-trip MtA
  exchange and identifiable-abort detection), the session-bound key guard,
  constant-time comparison utilities, the policy engine, the immutable
  audit chain, and the software-simulation HSM driver.
- Test count increased from 5 files to 12 files.

## [6.0.0] - 2026-08-07

### Security
- Fixed nonce reuse vulnerability in threshold signing
- Replaced XOR stream cipher with AES-256-GCM authenticated encryption
- Implemented proper Fiat-Shamir NIZK range proofs for MtA
- Added constant-time comparison operations
- Added input sanitization and validation
- Added Redis-backed rate limiting
- Added security headers (Helmet)

### Features
- Production MPC-CMP protocol engine
- Paillier homomorphic encryption (2048-bit)
- Multi-chain address derivation (EVM, Bitcoin, Solana, Polkadot)
- Institutional policy engine with velocity limits
- Immutable SHA-256 audit chain with Merkle verification
- HSM integration (AWS KMS, Azure, GCP, PKCS#11)
- Prometheus metrics export
- Winston structured logging
- Docker + Kubernetes deployment

### Infrastructure
- Multi-stage Docker build
- Kubernetes manifests with security contexts
- PostgreSQL + Redis support
- Health checks and probes
