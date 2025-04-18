// File: src/main/java/org/example/iam/service/FileSystemCredentialService.java
package org.example.iam.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * Placeholder implementation of CredentialService that simulates loading
 * keys and certificates from PKCS#12 files on the filesystem.
 * Uses injected EncryptionService to decrypt stored password references.
 * <p>
 * **WARNING:** This implementation contains placeholder logic for file access
 * and lacks robust error handling and secure file path validation needed for production.
 * The core logic of loading from a KeyStore is shown, but secure path handling
 * and potentially more sophisticated password management are required.
 * </p>
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class FileSystemCredentialService implements CredentialService {

    private final EncryptionService encryptionService; // Inject EncryptionService

    @Override
    public PrivateKey loadPrivateKey(String credentialRef, String keyAlias, String passwordRef) {
        log.debug("Attempting to load PrivateKey. Ref: '{}', Alias: '{}'. Password ref is encrypted.", credentialRef, keyAlias);
        if (!StringUtils.hasText(credentialRef) || !StringUtils.hasText(keyAlias) || !StringUtils.hasText(passwordRef)) {
            log.error("Cannot load private key: Missing credential reference, key alias, or encrypted password reference.");
            return null;
        }

        String keystorePassword;
        try {
            // Decrypt the password reference using the injected service
            keystorePassword = encryptionService.decrypt(passwordRef);
            if (keystorePassword == null) throw new IllegalArgumentException("Decrypted password was null");
        } catch (Exception e) {
            log.error("Failed to decrypt keystore password reference for path: {}", credentialRef, e);
            // Decide whether to throw ConfigurationException or return null based on policy
            throw new RuntimeException("Failed to decrypt keystore password reference", e);
        }

        try {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            // *** PLACEHOLDER: Replace with secure file loading logic ***
            // This assumes credentialRef is a direct file path - requires validation!
            try (InputStream is = new FileInputStream(credentialRef)) {
                log.debug("Loading PKCS12 keystore from path: {}", credentialRef);
                keyStore.load(is, keystorePassword.toCharArray());
            } catch (FileNotFoundException e) {
                log.error("Keystore file not found at path: {}", credentialRef);
                throw e; // Re-throw specific exception
            }

            // Assuming key password is same as keystore password for simplicity.
            // Real implementation might need a separate key password.
            PrivateKey key = (PrivateKey) keyStore.getKey(keyAlias, keystorePassword.toCharArray());
            if (key == null) {
                log.error("Private key with alias '{}' not found in keystore '{}'", keyAlias, credentialRef);
                return null;
            }
            log.info("Successfully loaded Private Key with alias '{}' from reference '{}'", keyAlias, credentialRef);
            return key;
        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException | UnrecoverableKeyException e) {
            log.error("Failed to load private key alias '{}' from reference '{}': {}", keyAlias, credentialRef, e.getMessage(), e);
            // Throw a runtime exception indicating configuration/loading failure
            throw new RuntimeException("Failed to load private key from keystore reference: " + credentialRef, e);
        } catch (Exception e) { // Catch unexpected errors
            log.error("Unexpected error loading private key alias '{}' from reference '{}': {}", keyAlias, credentialRef, e.getMessage(), e);
            throw new RuntimeException("Unexpected error loading private key from keystore reference: " + credentialRef, e);
        }
    }

    @Override
    public X509Certificate loadCertificate(String credentialRef, String keyAlias, String passwordRef) {
        log.debug("Attempting to load Certificate. Ref: '{}', Alias: '{}'. Password ref is encrypted.", credentialRef, keyAlias);
        if (!StringUtils.hasText(credentialRef) || !StringUtils.hasText(keyAlias) || !StringUtils.hasText(passwordRef)) {
            log.error("Cannot load certificate from keystore: Missing credential reference, key alias, or encrypted password reference.");
            return null;
        }

        String keystorePassword;
        try {
            // Decrypt the password reference
            keystorePassword = encryptionService.decrypt(passwordRef);
            if (keystorePassword == null) throw new IllegalArgumentException("Decrypted password was null");
        } catch (Exception e) {
            log.error("Failed to decrypt keystore password reference for path: {}", credentialRef, e);
            throw new RuntimeException("Failed to decrypt keystore password reference", e);
        }

        try {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            // *** PLACEHOLDER: Replace with secure file loading logic ***
            try (InputStream is = new FileInputStream(credentialRef)) {
                log.debug("Loading PKCS12 keystore from path: {}", credentialRef);
                keyStore.load(is, keystorePassword.toCharArray());
            } catch (FileNotFoundException e) {
                log.error("Keystore file not found at path: {}", credentialRef);
                throw e;
            }

            X509Certificate cert = (X509Certificate) keyStore.getCertificate(keyAlias);
            if (cert == null) {
                log.error("Certificate with alias '{}' not found in keystore '{}'", keyAlias, credentialRef);
                return null;
            }
            log.info("Successfully loaded Certificate with alias '{}' from reference '{}'", keyAlias, credentialRef);
            return cert;
        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
            log.error("Failed to load certificate alias '{}' from reference '{}': {}", keyAlias, credentialRef, e.getMessage(), e);
            throw new RuntimeException("Failed to load certificate from keystore reference: " + credentialRef, e);
        } catch (Exception e) { // Catch unexpected errors
            log.error("Unexpected error loading certificate alias '{}' from reference '{}': {}", keyAlias, credentialRef, e.getMessage(), e);
            throw new RuntimeException("Unexpected error loading certificate from keystore reference: " + credentialRef, e);
        }
    }

    @Override
    public X509Certificate loadCertificateFromPem(String pemData) {
        if (!StringUtils.hasText(pemData)) {
            log.warn("Attempted to load certificate from empty PEM data.");
            return null;
        }
        log.debug("Attempting to load certificate from PEM data.");
        try {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            try (InputStream is = new ByteArrayInputStream(pemData.getBytes(StandardCharsets.UTF_8))) {
                X509Certificate cert = (X509Certificate) factory.generateCertificate(is);
                log.info("Successfully loaded certificate from PEM data.");
                return cert;
            }
        } catch (CertificateException | IOException e) {
            log.error("Failed to load certificate from PEM data: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to parse certificate from PEM data", e);
        }
    }
}