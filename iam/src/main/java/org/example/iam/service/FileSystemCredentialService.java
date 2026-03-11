// File: src/main/java/org/example/iam/service/FileSystemCredentialService.java
package org.example.iam.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.iam.exception.ConfigurationException;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.*;
import java.util.Base64;
import java.util.Collections; // Import Collections for listing aliases

/**
 * Filesystem implementation of CredentialService using PKCS#12.
 * Handles separate keystore and key passwords.
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class FileSystemCredentialService implements CredentialService {

    private final EncryptionService encryptionService;

    // loadPrivateKey now uses the updated interface signature AND uses separate key password
    @Override
    public PrivateKey loadPrivateKey(String credentialRef, String keyAlias, String keystorePasswordRef, String keyPasswordRef) {
        log.debug("Attempting to load PrivateKey. Ref: '{}', Alias: '{}'. Passwords refs are encrypted.", credentialRef, keyAlias);
        if (!StringUtils.hasText(credentialRef) || !StringUtils.hasText(keyAlias) || !StringUtils.hasText(keystorePasswordRef)) {
            log.error("Cannot load private key: Missing required references (path, alias, keystore password).");
            throw new ConfigurationException("Missing required credential references for private key loading.");
        }

        String keystorePassword;
        String keyPassword; // Password specifically for the key alias

        try {
            // Decrypt keystore password (mandatory)
            keystorePassword = encryptionService.decrypt(keystorePasswordRef);
            if (keystorePassword == null) throw new ConfigurationException("Decrypted keystore password was null");

            // Decrypt key password IF provided, otherwise use keystore password
            if (StringUtils.hasText(keyPasswordRef)) {
                keyPassword = encryptionService.decrypt(keyPasswordRef);
                if (keyPassword == null) throw new ConfigurationException("Decrypted key alias password was null (it was provided but decryption failed)");
                log.debug("Using separate decrypted password for key alias '{}'", keyAlias);
            } else {
                keyPassword = keystorePassword; // Fallback to use keystore password for the key
                log.debug("No separate key alias password ref provided for '{}', using keystore password for key.", keyAlias);
            }

        } catch (Exception e) {
            log.error("Failed to decrypt keystore or key password reference for path: {}", credentialRef, e);
            throw new ConfigurationException("Failed to decrypt password reference(s) for keystore: " + credentialRef, e);
        }

        // --- Load Keystore and Extract Key ---
        try {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            // *** WARNING: Replace with secure file loading logic for production ***
            try (InputStream is = new FileInputStream(credentialRef)) {
                log.debug("Loading PKCS12 keystore from path: {}", credentialRef);
                keyStore.load(is, keystorePassword.toCharArray()); // Load keystore with keystore password
            } catch (FileNotFoundException e) {
                log.error("Keystore file not found at path: {}", credentialRef);
                throw new ConfigurationException("Keystore file not found: " + credentialRef, e);
            } catch (IOException e) {
                log.error("Failed to load keystore file '{}' (IOException - possibly wrong password or corrupted file): {}", credentialRef, e.getMessage());
                throw new ConfigurationException("Failed to load keystore file (check password/integrity): " + credentialRef, e);
            }

            // Use the potentially separate keyPassword to get the key
            Key key = keyStore.getKey(keyAlias, keyPassword.toCharArray()); // <<< USE keyPassword

            if (key == null) {
                log.error("Private key with alias '{}' not found in keystore '{}'. Available aliases: {}", keyAlias, credentialRef, Collections.list(keyStore.aliases()));
                throw new ConfigurationException("Private key alias '" + keyAlias + "' not found in keystore: " + credentialRef);
            }
            if (!(key instanceof PrivateKey)) {
                log.error("Key with alias '{}' in keystore '{}' is not a PrivateKey. Actual type: {}", keyAlias, credentialRef, key.getClass().getName());
                throw new ConfigurationException("Key alias '" + keyAlias + "' in keystore " + credentialRef + " is not a private key.");
            }

            log.info("Successfully loaded Private Key with alias '{}' from reference '{}'", keyAlias, credentialRef);
            return (PrivateKey) key;
        } catch (UnrecoverableKeyException e){
            log.error("Failed to load private key alias '{}' from reference '{}' - Incorrect key password provided.", keyAlias, credentialRef, e);
            throw new ConfigurationException("Incorrect password for private key alias '" + keyAlias + "' in keystore: " + credentialRef, e);
        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException e) {
            log.error("Failed to load private key alias '{}' from reference '{}': {}", keyAlias, credentialRef, e.getMessage(), e);
            throw new ConfigurationException("General crypto error loading private key: " + credentialRef, e);
        } catch (Exception e) {
            log.error("Unexpected error loading private key alias '{}' from reference '{}': {}", keyAlias, credentialRef, e.getMessage(), e);
            throw new RuntimeException("Unexpected error loading private key from keystore reference: " + credentialRef, e);
        }
    }

    // --- loadCertificate and loadCertificateFromPem remain unchanged ---
    @Override
    public X509Certificate loadCertificate(String credentialRef, String keyAlias, String keystorePasswordRef) {
        // ... (Implementation unchanged) ...
        log.debug("Attempting to load Certificate. Ref: '{}', Alias: '{}'.", credentialRef, keyAlias);
        if (!StringUtils.hasText(credentialRef) || !StringUtils.hasText(keyAlias) || !StringUtils.hasText(keystorePasswordRef)) { log.error("Cannot load certificate..."); return null; }
        String keystorePassword;
        try { keystorePassword = encryptionService.decrypt(keystorePasswordRef); if (keystorePassword == null) throw new ConfigurationException("Decrypted keystore password was null"); } catch (Exception e) { log.error("Failed to decrypt keystore password ref: {}", e.getMessage(), e); throw new ConfigurationException("...", e); }
        try {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            try (InputStream is = new FileInputStream(credentialRef)) { keyStore.load(is, keystorePassword.toCharArray()); } catch (FileNotFoundException e) { log.error("Keystore file not found: {}", credentialRef); throw new ConfigurationException("...", e); } catch (IOException e) { log.error("Failed to load keystore file '{}': {}", credentialRef, e.getMessage()); throw new ConfigurationException("...", e); }
            X509Certificate cert = (X509Certificate) keyStore.getCertificate(keyAlias);
            if (cert == null) { log.error("Certificate alias '{}' not found in keystore '{}'", keyAlias, credentialRef); throw new ConfigurationException("Certificate alias not found"); }
            log.info("Successfully loaded Certificate alias '{}' from reference '{}'", keyAlias, credentialRef);
            return cert;
        } catch (Exception e) { log.error("Error loading certificate alias '{}' from ref '{}': {}", keyAlias, credentialRef, e.getMessage(), e); throw new ConfigurationException("...", e); }
    }

    @Override
    public X509Certificate loadCertificateFromPem(String pemData) {
        // ... (Implementation unchanged) ...
        if (!StringUtils.hasText(pemData)) return null;
        log.debug("Attempting to load certificate from PEM data.");
        try { CertificateFactory factory = CertificateFactory.getInstance("X.509"); try (InputStream is = new ByteArrayInputStream(pemData.getBytes(StandardCharsets.UTF_8))) { return (X509Certificate) factory.generateCertificate(is); } } catch (Exception e) { log.error("Failed to load certificate from PEM: {}", e.getMessage(), e); throw new RuntimeException("...", e); }
    }
}