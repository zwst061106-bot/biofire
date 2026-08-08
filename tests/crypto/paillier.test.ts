import { describe, it, expect } from 'vitest';
import { generatePaillierKeys, encryptPaillier, decryptPaillier, addEncrypted, multiplyEncryptedByScalar } from '../../src/lib/crypto/paillier.js';

describe('Paillier Cryptosystem', () => {
  it('should encrypt and decrypt correctly', () => {
    const { publicKey, privateKey } = generatePaillierKeys(1024); // 1024 for test speed
    const plaintext = 42n;
    const ciphertext = encryptPaillier(publicKey, plaintext);
    const decrypted = decryptPaillier(privateKey, publicKey, ciphertext);
    expect(decrypted).toBe(plaintext);
  });

  it('should support homomorphic addition', () => {
    const { publicKey, privateKey } = generatePaillierKeys(1024);
    const m1 = 10n, m2 = 20n;
    const c1 = encryptPaillier(publicKey, m1);
    const c2 = encryptPaillier(publicKey, m2);
    const cSum = addEncrypted(publicKey, c1, c2);
    const decrypted = decryptPaillier(privateKey, publicKey, cSum);
    expect(decrypted).toBe(30n);
  });

  it('should support homomorphic scalar multiplication', () => {
    const { publicKey, privateKey } = generatePaillierKeys(1024);
    const m = 5n;
    const c = encryptPaillier(publicKey, m);
    const cMul = multiplyEncryptedByScalar(publicKey, c, 3n);
    const decrypted = decryptPaillier(privateKey, publicKey, cMul);
    expect(decrypted).toBe(15n);
  });

  it('should reject plaintext >= n', () => {
    const { publicKey } = generatePaillierKeys(1024);
    expect(() => encryptPaillier(publicKey, publicKey.n)).toThrow();
  });
});
