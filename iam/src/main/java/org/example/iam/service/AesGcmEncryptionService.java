// File: src/main/java/org/example/iam/service/AesGcmEncryptionService.java
package org.example.iam.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import jakarta.annotation.PostConstruct; // Use jakarta annotation
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Implementation of EncryptionService using AES/GCM/NoPadding.
 * AES/GCM provides authenticated encryption (confidentiality and integrity).
 * Requires a secure, Base64 encoded AES key (256-bit recommended) provided via
 * the 'app.encryption.key' application property or APP_ENCRYPTION_KEY environment variable.
 */
@Service
@Slf4j
public class AesGcmEncryptionService implements EncryptionService {

    @Value("${app.encryption.key:${APP_ENCRYPTION_KEY:}}") // Looks for 'app.encryption.key' property OR 'APP_ENCRYPTION_KEY' env var
    private String base64EncodedKey;

    private SecretKey secretKey;
    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int GCM_IV_LENGTH = 12; // 96 bits recommended for GCM
    private static final int GCM_TAG_LENGTH = 128; // bits
    private static final SecureRandom secureRandom = new SecureRandom();

    /**
     * Initializes the service by decoding the key after properties are set.
     * Throws IllegalStateException if the key is missing or invalid.
     */
    @PostConstruct
    private void init() {
        if (!StringUtils.hasText(base64EncodedKey)) {
            log.error("!!! CRITICAL: Application encryption key (app.encryption.key or APP_ENCRYPTION_KEY) is not configured! Encryption/Decryption will fail. !!!");
            throw new IllegalStateException("Application encryption key is not configured.");
        }
        try {
            byte[] decodedKey = Base64.getDecoder().decode(base64EncodedKey);
            // Basic check for common AES key sizes (16, 24, 32 bytes)
            if (decodedKey.length != 16 && decodedKey.length != 24 && decodedKey.length != 32) {
                log.error("!!! CRITICAL: Invalid AES key length ({} bytes). Must be 16, 24, or 32 bytes after Base64 decoding. !!!", decodedKey.length);
                throw new IllegalArgumentException("Invalid AES key length.");
            }
            this.secretKey = new SecretKeySpec(decodedKey, "AES");
            log.info("EncryptionService initialized successfully with {} -bit AES key.", decodedKey.length * 8);
        } catch (IllegalArgumentException e) {
            log.error("!!! CRITICAL: Invalid Base64 encoding for application encryption key. !!!", e);
            throw new IllegalStateException("Invalid Base64 encoding for application encryption key.", e);
        }
    }

    @Override
    public String encrypt(String plaintext) {
        if (plaintext == null) {
            return null;
        }
        if (secretKey == null) {
            throw new IllegalStateException("Encryption service not initialized properly (key is missing).");
        }
        try {
            byte[] iv = new byte[GCM_IV_LENGTH];
            secureRandom.nextBytes(iv); // Generate random IV

            Cipher cipher = Cipher.getInstance(ALGORITHM);
            GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);

            byte[] cipherTextBytes = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

            // Prepend IV to ciphertext for storage/transmission
            byte[] encryptedData = new byte[iv.length + cipherTextBytes.length];
            System.arraycopy(iv, 0, encryptedData, 0, iv.length);
            System.arraycopy(cipherTextBytes, 0, encryptedData, iv.length, cipherTextBytes.length);

            // Return Base64 encoded string (IV + Ciphertext)
            return Base64.getEncoder().encodeToString(encryptedData);
        } catch (GeneralSecurityException e) {
            log.error("Encryption failed: {}", e.getMessage(), e);
            throw new RuntimeException("Encryption failed", e);
        }
    }

    @Override
    public String decrypt(String ciphertext) {
        if (ciphertext == null) {
            return null;
        }
        if (secretKey == null) {
            throw new IllegalStateException("Encryption service not initialized properly (key is missing).");
        }
        try {
            byte[] encryptedData = Base64.getDecoder().decode(ciphertext);

            // Extract IV from the beginning
            if (encryptedData.length < GCM_IV_LENGTH) {
                throw new IllegalArgumentException("Invalid ciphertext length: cannot extract IV.");
            }
            byte[] iv = new byte[GCM_IV_LENGTH];
            System.arraycopy(encryptedData, 0, iv, 0, iv.length);

            // Extract actual ciphertext
            byte[] cipherTextBytes = new byte[encryptedData.length - GCM_IV_LENGTH];
            System.arraycopy(encryptedData, GCM_IV_LENGTH, cipherTextBytes, 0, cipherTextBytes.length);

            Cipher cipher = Cipher.getInstance(ALGORITHM);
            GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, parameterSpec);

            byte[] decryptedBytes = cipher.doFinal(cipherTextBytes);

            return new String(decryptedBytes, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException | GeneralSecurityException e) {
            // Handles Base64 errors, length errors, decryption errors (like tag mismatch)
            log.error("Decryption failed: {}. Ciphertext prefix: {}", e.getMessage(), ciphertext.substring(0, Math.min(ciphertext.length(), 10)) + "...", e);
            throw new RuntimeException("Decryption failed. Check if the ciphertext is valid/unaltered and the encryption key is correct.", e);
        }
    }
}