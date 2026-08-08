# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 6.0.x   | ✅ Yes |
| 5.0.x   | ⚠️ Limited support |
| < 5.0   | ❌ No |

## Reporting a Vulnerability

Please report security vulnerabilities to security@biofire.dev with:
- Description of the vulnerability
- Steps to reproduce
- Potential impact assessment
- Suggested fix (if any)

We will respond within 48 hours and provide a timeline for resolution.

## Security Measures

- All cryptographic operations use audited libraries (@noble/curves)
- MPC protocol follows CMP-CMP (Canetti et al.) specification
- HSM integration for key material protection
- Immutable audit trail for all operations
- **No third-party security audit has been performed on this codebase.** A professional audit is strongly recommended before any production deployment handling real funds.

## Known `npm audit` Findings

`npm audit` currently reports vulnerabilities in `esbuild`/`vite`, pulled in transitively via the `vitest` **devDependency**. These packages are not part of the production `dependencies` and are not present in the deployed runtime — they affect the local development/test server only. They do not require immediate action, but are tracked here for transparency.
