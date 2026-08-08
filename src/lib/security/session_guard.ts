/**
 * Production Session-Bound Key Guard
 * Uses AES-256-GCM (Authenticated Encryption) instead of XOR.
 * Dual-authentication: JWT + Cookie fingerprint.
 */

import { sha256 } from '@noble/hashes/sha256';
import { hmac } from '@noble/hashes/hmac';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import { secureRandomBytes } from './secure_random';

export interface SessionBindingTokens {
  jwtToken: string;
  cookieFingerprint: string;
  sessionId: string;
  expiresAt: number;
}

export interface EncryptedBoundShare {
  shareId: string;
  wrappedDataHex: string;
  ivHex: string;
  saltHex: string;
  authTagHex: string;
  sessionBindingHash: string;
  algorithm: string;
}

export class SessionBoundKeyGuard {
  private static activeSessions = new Map<string, SessionBindingTokens>();
  private static readonly ALGORITHM = 'AES-256-GCM';
  private static readonly SESSION_TTL_MS = 3600 * 1000; // 1 hour

  /**
   * Create a new cryptographically secure session binding.
   */
  static createSessionBinding(sessionId: string): SessionBindingTokens {
    const rawJwt = bytesToHex(secureRandomBytes(32));
    const rawCookie = bytesToHex(secureRandomBytes(32));
    const jwtToken = `bf_jwt_${rawJwt}`;
    const cookieFingerprint = `bf_cookie_${rawCookie}`;
    const expiresAt = Date.now() + this.SESSION_TTL_MS;

    const binding: SessionBindingTokens = {
      jwtToken,
      cookieFingerprint,
      sessionId,
      expiresAt,
    };

    this.activeSessions.set(sessionId, binding);
    return binding;
  }

  /**
   * Derive AES-256 key from JWT + Cookie + Salt using HKDF-like construction.
   */
  private static deriveKey(jwtToken: string, cookieFingerprint: string, salt: Uint8Array): Uint8Array {
    const combined = new TextEncoder().encode(`${jwtToken}:${cookieFingerprint}`);
    return hmac(sha256, salt, combined);
  }

  /**
   * Wrap a raw MPC key share with session-bound AES-256-GCM encryption.
   */
  static async wrapShareWithSessionTokens(
    shareId: string,
    rawShareBytes: Uint8Array,
    tokens: SessionBindingTokens
  ): Promise<EncryptedBoundShare> {
    const salt = secureRandomBytes(32);
    const iv = secureRandomBytes(16); // GCM recommends 96-bit (12 bytes) but 128-bit (16 bytes) is also valid
    const key = this.deriveKey(tokens.jwtToken, tokens.cookieFingerprint, salt);

    // Import key for Web Crypto API
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      key,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt']
    );

    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      cryptoKey,
      rawShareBytes
    );

    const combined = new Uint8Array(ciphertext);
    const authTag = combined.slice(-16); // Last 16 bytes are GCM auth tag
    const encryptedData = combined.slice(0, -16);

    const bindingInput = new TextEncoder().encode(
      `${tokens.sessionId}:${tokens.jwtToken}:${tokens.cookieFingerprint}`
    );
    const bindingHash = bytesToHex(sha256(bindingInput));

    return {
      shareId,
      wrappedDataHex: '0x' + bytesToHex(encryptedData),
      ivHex: '0x' + bytesToHex(iv),
      saltHex: '0x' + bytesToHex(salt),
      authTagHex: '0x' + bytesToHex(authTag),
      sessionBindingHash: '0x' + bindingHash,
      algorithm: this.ALGORITHM,
    };
  }

  /**
   * Unwrap a session-bound MPC key share.
   * Fails strictly if JWT, Cookie, or session is invalid/expired.
   */
  static async unwrapShareWithSessionTokens(
    boundShare: EncryptedBoundShare,
    jwtToken: string,
    cookieFingerprint: string,
    sessionId: string
  ): Promise<Uint8Array> {
    // 1. Verify session validity
    const activeSession = this.activeSessions.get(sessionId);
    if (!activeSession || activeSession.expiresAt < Date.now()) {
      throw new Error('UNAUTHORIZED_SESSION_EXPIRED: Active MPC session cookie/token expired or invalid.');
    }

    // 2. Verify Cookie & JWT match
    if (activeSession.jwtToken !== jwtToken || activeSession.cookieFingerprint !== cookieFingerprint) {
      throw new Error('UNAUTHORIZED_SESSION_MISMATCH: Provided cookie or JWT token does not match active session binding.');
    }

    // 3. Verify binding hash
    const bindingInput = new TextEncoder().encode(`${sessionId}:${jwtToken}:${cookieFingerprint}`);
    const expectedBindingHash = '0x' + bytesToHex(sha256(bindingInput));
    if (expectedBindingHash !== boundShare.sessionBindingHash) {
      throw new Error('UNAUTHORIZED_SESSION_TAMPERED: Cookie / Token binding hash mismatch!');
    }

    // 4. Decrypt with AES-256-GCM
    const salt = hexToBytes(boundShare.saltHex.replace(/^0x/, ''));
    const iv = hexToBytes(boundShare.ivHex.replace(/^0x/, ''));
    const encryptedData = hexToBytes(boundShare.wrappedDataHex.replace(/^0x/, ''));
    const authTag = hexToBytes(boundShare.authTagHex.replace(/^0x/, ''));

    const key = this.deriveKey(jwtToken, cookieFingerprint, salt);
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      key,
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt']
    );

    // Combine ciphertext + authTag for GCM decryption
    const combined = new Uint8Array(encryptedData.length + authTag.length);
    combined.set(encryptedData, 0);
    combined.set(authTag, encryptedData.length);

    try {
      const plaintext = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv },
        cryptoKey,
        combined
      );
      return new Uint8Array(plaintext);
    } catch {
      throw new Error('UNAUTHORIZED_DECRYPTION_FAILED: Auth tag verification failed. Data tampered or wrong key.');
    }
  }

  /**
   * Revoke a session immediately.
   */
  static revokeSession(sessionId: string): boolean {
    return this.activeSessions.delete(sessionId);
  }

  /**
   * Validate request auth tokens.
   */
  static validateRequestAuthTokens(
    authHeader?: string,
    cookieHeader?: string,
    sessionId?: string
  ): { isValid: boolean; jwtToken?: string; cookieFingerprint?: string; reason?: string } {
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return { isValid: false, reason: 'Missing or malformed Authorization Bearer token header' };
    }

    if (!cookieHeader || !cookieHeader.includes('biofire_session_auth=')) {
      return { isValid: false, reason: 'Missing or invalid httpOnly biofire_session_auth cookie' };
    }

    const jwtToken = authHeader.replace('Bearer ', '').trim();
    const cookieMatch = cookieHeader.match(/biofire_session_auth=([^;]+)/);
    const cookieFingerprint = cookieMatch ? cookieMatch[1].trim() : '';

    if (sessionId) {
      const active = this.activeSessions.get(sessionId);
      if (!active || active.jwtToken !== jwtToken || active.cookieFingerprint !== cookieFingerprint) {
        return { isValid: false, reason: 'Session token or cookie fingerprint mismatch' };
      }
      if (active.expiresAt < Date.now()) {
        return { isValid: false, reason: 'Session expired' };
      }
    }

    return { isValid: true, jwtToken, cookieFingerprint };
  }

  /**
   * Clean up expired sessions.
   */
  static cleanupExpiredSessions(): number {
    const now = Date.now();
    let removed = 0;
    for (const [id, session] of this.activeSessions) {
      if (session.expiresAt < now) {
        this.activeSessions.delete(id);
        removed++;
      }
    }
    return removed;
  }
}
