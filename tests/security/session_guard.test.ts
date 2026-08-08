import { describe, it, expect } from 'vitest';
import { SessionBoundKeyGuard } from '../../src/lib/security/session_guard.js';

describe('SessionBoundKeyGuard', () => {
  it('wraps and unwraps a key share round-trip correctly', async () => {
    const sessionId = 'sess-' + Math.random().toString(36).slice(2);
    const tokens = SessionBoundKeyGuard.createSessionBinding(sessionId);
    const raw = new TextEncoder().encode('super-secret-key-share-material');

    const wrapped = await SessionBoundKeyGuard.wrapShareWithSessionTokens('share-1', raw, tokens);
    const unwrapped = await SessionBoundKeyGuard.unwrapShareWithSessionTokens(
      wrapped,
      tokens.jwtToken,
      tokens.cookieFingerprint,
      sessionId
    );

    expect(new TextDecoder().decode(unwrapped)).toBe('super-secret-key-share-material');
  });

  it('rejects unwrap with a mismatched JWT token', async () => {
    const sessionId = 'sess-' + Math.random().toString(36).slice(2);
    const tokens = SessionBoundKeyGuard.createSessionBinding(sessionId);
    const raw = new TextEncoder().encode('secret');
    const wrapped = await SessionBoundKeyGuard.wrapShareWithSessionTokens('share-2', raw, tokens);

    await expect(
      SessionBoundKeyGuard.unwrapShareWithSessionTokens(
        wrapped,
        'bf_jwt_wrong',
        tokens.cookieFingerprint,
        sessionId
      )
    ).rejects.toThrow(/UNAUTHORIZED_SESSION_MISMATCH/);
  });

  it('rejects unwrap for a revoked session', async () => {
    const sessionId = 'sess-' + Math.random().toString(36).slice(2);
    const tokens = SessionBoundKeyGuard.createSessionBinding(sessionId);
    const raw = new TextEncoder().encode('secret');
    const wrapped = await SessionBoundKeyGuard.wrapShareWithSessionTokens('share-3', raw, tokens);

    SessionBoundKeyGuard.revokeSession(sessionId);

    await expect(
      SessionBoundKeyGuard.unwrapShareWithSessionTokens(
        wrapped,
        tokens.jwtToken,
        tokens.cookieFingerprint,
        sessionId
      )
    ).rejects.toThrow(/UNAUTHORIZED_SESSION_EXPIRED/);
  });

  it('rejects unwrap for an unknown session id', async () => {
    await expect(
      SessionBoundKeyGuard.unwrapShareWithSessionTokens(
        {
          shareId: 'x',
          wrappedDataHex: '0x00',
          ivHex: '0x' + '00'.repeat(16),
          saltHex: '0x' + '00'.repeat(32),
          authTagHex: '0x' + '00'.repeat(16),
          sessionBindingHash: '0x00',
          algorithm: 'AES-256-GCM',
        },
        'bf_jwt_x',
        'bf_cookie_x',
        'nonexistent-session'
      )
    ).rejects.toThrow(/UNAUTHORIZED_SESSION_EXPIRED/);
  });

  it('validates well-formed request auth headers', () => {
    const result = SessionBoundKeyGuard.validateRequestAuthTokens(
      'Bearer bf_jwt_abc123',
      'biofire_session_auth=bf_cookie_abc123; Path=/',
      undefined
    );
    expect(result.isValid).toBe(true);
    expect(result.jwtToken).toBe('bf_jwt_abc123');
  });

  it('rejects a request missing the Authorization header', () => {
    const result = SessionBoundKeyGuard.validateRequestAuthTokens(
      undefined,
      'biofire_session_auth=bf_cookie_abc123',
      undefined
    );
    expect(result.isValid).toBe(false);
  });

  it('rejects a request missing the session cookie', () => {
    const result = SessionBoundKeyGuard.validateRequestAuthTokens('Bearer bf_jwt_abc', undefined, undefined);
    expect(result.isValid).toBe(false);
  });

  it('cleans up expired sessions', () => {
    const sessionId = 'sess-cleanup-' + Math.random().toString(36).slice(2);
    SessionBoundKeyGuard.createSessionBinding(sessionId);
    SessionBoundKeyGuard.revokeSession(sessionId);
    // revoked session is already gone; cleanup should not throw and returns a count >= 0
    expect(SessionBoundKeyGuard.cleanupExpiredSessions()).toBeGreaterThanOrEqual(0);
  });
});
