import { describe, it, expect } from 'vitest';
import { SoftwareSimulationHSMDriver, getHSMDriver } from '../../src/lib/crypto/hsm_enclave.js';
import { secureRandomBytes } from '../../src/lib/security/secure_random.js';

describe('SoftwareSimulationHSMDriver', () => {
  it('is explicitly marked as a simulation, never a real HSM', () => {
    const driver = new SoftwareSimulationHSMDriver();
    expect(driver.isSimulation).toBe(true);
    expect(driver.providerName).toContain('DEV ONLY');
  });

  it('encrypts and decrypts a share round-trip with the same master secret', async () => {
    const driver = new SoftwareSimulationHSMDriver();
    const masterSecret = secureRandomBytes(32);
    const shareData = new TextEncoder().encode('mpc-key-share-material');

    await driver.encryptShare('share-a', shareData, masterSecret);
    const decrypted = await driver.decryptShare('share-a', masterSecret);

    expect(new TextDecoder().decode(decrypted)).toBe('mpc-key-share-material');
  });

  it('fails to decrypt with the wrong master secret', async () => {
    const driver = new SoftwareSimulationHSMDriver();
    const masterSecret = secureRandomBytes(32);
    const wrongSecret = secureRandomBytes(32);
    const shareData = new TextEncoder().encode('secret-share');

    await driver.encryptShare('share-b', shareData, masterSecret);
    await expect(driver.decryptShare('share-b', wrongSecret)).rejects.toThrow();
  });

  it('throws when decrypting a share id that was never stored', async () => {
    const driver = new SoftwareSimulationHSMDriver();
    await expect(driver.decryptShare('does-not-exist')).rejects.toThrow(/not found/);
  });

  it('reports HEALTHY status with a growing share count', async () => {
    const driver = new SoftwareSimulationHSMDriver();
    const secret = secureRandomBytes(32);
    await driver.encryptShare('s1', new TextEncoder().encode('a'), secret);
    await driver.encryptShare('s2', new TextEncoder().encode('b'), secret);

    const status = await driver.getEnclaveStatus();
    expect(status.status).toBe('HEALTHY');
    expect(status.keySharesEncrypted).toBe(2);
  });

  it('locks the enclave on zeroize and rejects further operations', async () => {
    const driver = new SoftwareSimulationHSMDriver();
    const secret = secureRandomBytes(32);
    await driver.encryptShare('s1', new TextEncoder().encode('a'), secret);

    await driver.zeroize();
    const status = await driver.getEnclaveStatus();
    expect(status.status).toBe('TAMPERED');
    expect(status.keySharesEncrypted).toBe(0);

    await expect(driver.encryptShare('s2', new TextEncoder().encode('b'), secret)).rejects.toThrow(/LOCKED/);
  });

  it('recovers to HEALTHY after resetAndAttest', async () => {
    const driver = new SoftwareSimulationHSMDriver();
    await driver.zeroize();
    await driver.resetAndAttest();
    const status = await driver.getEnclaveStatus();
    expect(status.status).toBe('HEALTHY');
  });

  it('getHSMDriver returns the simulation driver by default', () => {
    const driver = getHSMDriver('simulation');
    expect(driver.isSimulation).toBe(true);
  });

  it('getHSMDriver throws for an AWS KMS driver with no key configured', () => {
    const original = process.env.AWS_KMS_KEY_ID;
    delete process.env.AWS_KMS_KEY_ID;
    expect(() => getHSMDriver('kms')).toThrow();
    if (original) process.env.AWS_KMS_KEY_ID = original;
  });
});
