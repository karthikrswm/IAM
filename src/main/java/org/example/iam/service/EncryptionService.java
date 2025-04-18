// File: src/main/java/org/example/iam/service/EncryptionService.java
package org.example.iam.service;

/**
 * Interface for a service providing symmetric encryption and decryption capabilities.
 * Used for securing sensitive configuration values like OAuth2 client secrets or
 * keystore passwords before storing them.
 */
public interface EncryptionService {

    /**
     * Encrypts the given plaintext string.
     *
     * @param plaintext The string to encrypt.
     * @return The Base64 encoded ciphertext.
     * @throws RuntimeException if encryption fails.
     */
    String encrypt(String plaintext);

    /**
     * Decrypts the given Base64 encoded ciphertext string.
     *
     * @param ciphertext The Base64 encoded ciphertext to decrypt.
     * @return The original plaintext string.
     * @throws RuntimeException if decryption fails (e.g., invalid format, incorrect key, tampered data).
     */
    String decrypt(String ciphertext);
}